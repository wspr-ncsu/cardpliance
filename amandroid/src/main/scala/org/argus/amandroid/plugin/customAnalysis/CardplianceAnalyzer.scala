package org.argus.amandroid.plugin.customAnalysis

import java.io.PrintWriter

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.dataRecorder.DataCollector
import org.argus.amandroid.alir.taintAnalysis.AndroidDataDependentTaintAnalysis.Tar
import org.argus.amandroid.core.parser.LayoutControl
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util.{FileUtil, ISet}
import org.argus.jawa.flow.cfg.ICFGCallNode
import org.argus.jawa.flow.dda.InterProceduralDataDependenceInfo
import org.argus.jawa.flow.taintAnalysis.{TaintAnalysisResult, TaintPath}
import org.argus.jawa.flow.util.ExplicitValueFinder

/**
  * @project argus-saf
  * @author samin on 5/4/19
  */
class CardplianceAnalyzer(yard: ApkYard, iddResult: (ISet[ApkGlobal], InterProceduralDataDependenceInfo), tar : Option[TaintAnalysisResult], apks : ISet[ApkGlobal]) {


   def runAnalyzer: Unit ={

     val ccComplianceFlag = true
     val cvcComplianceFlag = true
     val checkObfuscation = true
     val checkSecureNetworkEgress = true
     var checkInsecureApplicationEgress = true
     val checkMasking = true

     val hasCCNumberID = !yard.getApks.head._2.model.getUirefUriCC().equalsIgnoreCase(".")
     val hasCVCID = !yard.getApks.head._2.model.getUirefUriCVC().equalsIgnoreCase(".")
     val hasMaskingID = !yard.getApks.head._2.model.getDisplayWidget().equalsIgnoreCase(".")

     var persistCC = false
     var persistCVC = false
     var improperObfuscation = false
     var brokenSSL = false
     var httpUrls = false
     var improperMasking = false
     var insecureApplicationEgress = false

     var cardplianceUtils = new CardplianceUtils
     cardplianceUtils.matchSig(iddResult,tar.head,yard,"getText")

     //Test Compliance 1: CC Persisting inside app
     if(ccComplianceFlag && hasCCNumberID){
       val ccNumberRetentionCompliance = new CCNumberRetentionCompliance()
       val ccNumberPersistingTar =ccNumberRetentionCompliance.filterSourceSink(iddResult,tar.head,yard)
       println("Now getting tainted paths for cc")
       if(ccNumberPersistingTar!= null){
         val ccNumberPersistingPaths = ccNumberPersistingTar.getTaintedPaths

         if(ccNumberPersistingPaths.nonEmpty){
           println("Found tainted paths for cc")
           persistCC = true
           writeCustomResult(apks,getPathAsString(ccNumberPersistingPaths,yard),"CCComplianceResults")
           if(checkObfuscation){
             //Test 3 Obfuscation
             println("Testing proper obfuscation")
             val obfuscationCompliance = new ObfuscationCompliance
             val nonobfuscatedPaths : ISet[TaintPath] = obfuscationCompliance.isObfuscated(ccNumberPersistingPaths)
             if(nonobfuscatedPaths!=null && nonobfuscatedPaths.nonEmpty){
               improperObfuscation = true
               writeCustomResult(apks,getPathAsString(nonobfuscatedPaths,yard),"ObfuscationComplianceResult")
             }
             val obfuscatedPaths = ccNumberPersistingPaths.diff(nonobfuscatedPaths)
             if(obfuscatedPaths.nonEmpty)writeCustomResult(apks,getPathAsString(obfuscatedPaths,yard),"ObfuscatedPaths")
           }
         }

       }

     }

     //Test Compliance 2: CVC Persisting inside app
     if(ccComplianceFlag && hasCVCID){

       val cvcRetentionCompliance = new CVCRetentionCompliance()
       val cvcPersistingTar =cvcRetentionCompliance.filterSourceSink(iddResult,tar.head,yard)
       println("Now getting tainted paths for cvc")
       if(cvcPersistingTar!= null){
         val cvcPersistingPaths = cvcPersistingTar.getTaintedPaths
         if(cvcPersistingPaths.nonEmpty){
           println("Found tainted paths for cvc")
           persistCVC = true
           writeCustomResult(apks,getPathAsString(cvcPersistingPaths,yard),"CVCComplianceResult")

         }

       }


     }

     //Test Compliance 4: Secure Egress over network

     if(checkSecureNetworkEgress){

       val sslMisuseCompliance = new SSLMisuseCompliance

       println("Now checking for Broken SSL")

       sslMisuseCompliance.sslMisusecheck(iddResult,yard)

       val egressTar = sslMisuseCompliance.filterSourceSinks(iddResult,tar.head,yard)

       //sslMisuseCompliance.getPathsForInsecureEgress(tar.head,egressTar,yard)

       var secureEgressResult = ""
       if(sslMisuseCompliance.getSSLMisuseResult!= null){
         brokenSSL = sslMisuseCompliance.getSSLMisuse
         secureEgressResult += sslMisuseCompliance.getSSLMisuseResult
       }

       if(sslMisuseCompliance.getHTTPExists){
         httpUrls = true
         secureEgressResult += "\nHTTP Exists\n"

       }
       if(!sslMisuseCompliance.getUrlSet.equalsIgnoreCase("")){
         secureEgressResult += "List of URL where CC info are going to: \n"
         secureEgressResult += sslMisuseCompliance.getUrlSet
       }

       writeCustomResult(apks,secureEgressResult,"SecureNetworkEgress")

     }

     //Test Compliance 5: Insecure Application Egress
     if(checkInsecureApplicationEgress && hasCCNumberID){
       val secureApplicationEgressCompliance = new SecureApplicationEgressCompliance()
       val ccNumberSendingTar =secureApplicationEgressCompliance.filterSourceSink(iddResult,tar.head,yard)
       println("Now getting tainted paths for sending cc to external apps")
       if(ccNumberSendingTar!= null){
         val ccNumberSendingPaths = ccNumberSendingTar.getTaintedPaths

         if(ccNumberSendingPaths.nonEmpty){
           println("Found tainted paths for sending cc to external app")
           if(checkObfuscation){
             //Test 4 Obfuscation
             println("Testing proper obfuscation")
             val obfuscationCompliance = new ObfuscationCompliance
             val nonobfuscatedPaths : ISet[TaintPath] = obfuscationCompliance.isObfuscated(ccNumberSendingPaths)
             if(nonobfuscatedPaths!=null && nonobfuscatedPaths.nonEmpty){
               insecureApplicationEgress = true
               writeCustomResult(apks,getPathAsString(nonobfuscatedPaths,yard),"InsecureApplicationEgress")
             }
           }
         }

       }

     }

     //Test 6: Masking compliance
     if(checkMasking){
       val maskingCompliance = new MaskingCompliance
       val maskingComplianceTar = maskingCompliance.filterSourceSink(iddResult,tar.head,yard)
       if(maskingComplianceTar!= null){
         val p = maskingComplianceTar.getTaintedPaths
         if(maskingComplianceTar!= null && maskingComplianceTar.getTaintedPaths.nonEmpty){
           val paths : ISet[TaintPath] = maskingCompliance.removeUnnecessaryPathsFromUISource(tar.head,maskingComplianceTar,yard)
           if(paths.nonEmpty){

             val nonmaskedPaths : ISet[TaintPath] = maskingCompliance.isMasked(paths)
             if(nonmaskedPaths!=null && nonmaskedPaths.nonEmpty){
               improperMasking = true
               writeCustomResult(apks,getPathAsString(nonmaskedPaths,yard),"Masking")
             }
           }

         }
       }



     }



     //Generate over all report

     val sb = new StringBuilder
     sb.append("App Name, Collect CC, Persist CC, Collect CVC, Persist CVC, Improper Obfuscation, Broken SSL, Use HTTP, Improper Masking , Insecure Application Egress, Violate PCIDSS\n")

     sb.append(apks.head.model.getAppName+",")

     if(hasCCNumberID)sb.append("Y,")
     else sb.append("N,")

     if(persistCC)sb.append("Y,")
     else sb.append("N,")

     if(hasCVCID)sb.append("Y,")
     else sb.append("N,")

     if(persistCVC)sb.append("Y,")
     else sb.append("N,")

     if(improperObfuscation)sb.append("Y,")
     else sb.append("N,")

     if(brokenSSL)sb.append("Y,")
     else sb.append("N,")

     if(httpUrls)sb.append("Y,")
     else sb.append("N,")

     if(improperMasking)sb.append("Y,")
     else sb.append("N,")

     if(insecureApplicationEgress)sb.append("Y,")
     else sb.append("N,")

     if(persistCC || persistCVC || improperObfuscation || brokenSSL || httpUrls|| improperMasking)sb.append("Y")
     else sb.append("N")

     writeCustomResult(apks,sb.toString.intern(),"Report")


  }

  def getPathAsString (paths : ISet[TaintPath],yard: ApkYard) : String = {
    val sb = new StringBuilder
    if(paths.nonEmpty) {
      paths.foreach(tp => {
        sb.append(tp.getSource.descriptor+"\n")
        tp.getSource.node.node match {

          case cn :ICFGCallNode =>
            var flag = false
            yard.getApk(cn.getContext.application) match {
              case Some(apk) =>

                try {
                  val callerProc = apk.getMethod(cn.getOwner).get
                  val calleeSig = tp.getSource.descriptor.desc
                  if (calleeSig == AndroidConstants.ACTIVITY_FINDVIEWBYID || calleeSig == AndroidConstants.VIEW_FINDVIEWBYID) {

                    val callerLoc = callerProc.getBody.resolvedBody.locations(cn.locIndex)
                    val cs = callerLoc.statement.asInstanceOf[CallStatement]
                    val nums = ExplicitValueFinder.findExplicitLiteralForArgs(callerProc, callerLoc, cs.arg(0))
                    val control: LayoutControl = apk.model.getLayoutControls.get(nums.head.getInt).head
                    val widgetId: String = control.id.toString
                    sb.append("Widget ID: "+widgetId+"\n")
                  }
                } catch {
                  case _:Throwable => false
                }

              case _ =>
            }
            flag
          case _ => false
        }
        sb.append(tp.getSink.descriptor+"\n")
        sb.append("<taintpath>:\n")
        val  x = tp.getPath.toString
        val y = x.replaceAll(", #","\n")
        val z = y.substring(6,y.length-1)
        sb.append(z + "\n<\\taintpath>\n\n")
      })
    }
    sb.toString.intern()
  }

  private def writeCustomResult(apks: ISet[ApkGlobal], tar: String, complianceName: String): Unit = {
    println("Writing results")


    apks.foreach { apk =>
      val appData = DataCollector.collect(apk)
      val outputDirUri = FileUtil.appendFileName(apk.model.layout.outputSrcUri, "CardplianceReport")
      val outputDir = FileUtil.toFile(outputDirUri)
      if (!outputDir.exists()) outputDir.mkdirs()
      val out = new PrintWriter(FileUtil.toFile(FileUtil.appendFileName(outputDirUri, complianceName+".txt")))

      println()
      println("Results for "+complianceName)
      if(tar!= null) {
        out.print(tar)

      }
      out.close()
    }

    println("Writing done")
  }

}
