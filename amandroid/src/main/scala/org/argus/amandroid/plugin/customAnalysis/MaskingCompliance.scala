package org.argus.amandroid.plugin.customAnalysis

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.taintAnalysis.AndroidDataDependentTaintAnalysis.{Tar, relevantSources}
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.amandroid.core.parser.LayoutControl
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util.{ISet, MSet}
import org.argus.jawa.flow.cfg.ICFGCallNode
import org.argus.jawa.flow.dda.{DataDependenceBaseGraph, IDDGNode, InterProceduralDataDependenceAnalysis, InterProceduralDataDependenceInfo}
import org.argus.jawa.flow.taintAnalysis.{TaintAnalysisResult, TaintPath, TaintSource}
import org.argus.jawa.flow.util.ExplicitValueFinder

import scala.collection.mutable.ArrayBuffer
import scala.io.Source

/**
  * @project argus-saf
  * @author samin on 5/22/19
  */
class MaskingCompliance {

  private final val ccDisplayMethods: ISet[String] = Set(

    "Landroid/widget/TextView;.setText:(Ljava/lang/CharSequence;)V"
  )

  private final val relevantSources: ISet[String] = Set(

    "Landroid/content/SharedPreferences;.getString:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
    "Landroid/content/SharedPreferences?;.getString:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
    "Ljava/net/URLConnection;.getInputStream:()Ljava/io/InputStream;"

  )

  private final val maskingMethods: ISet[String] = Set(

    "append",
    "replace",
    "concat",
    "join",
    "split",
    "substring",
    "encode"
  )

  def filterSourceSink(iddResult: (ISet[ApkGlobal], InterProceduralDataDependenceInfo), tar:TaintAnalysisResult, yard: ApkYard): Tar ={

    var t = new Tar(iddResult._2)
    t.sourceNodes = tar.getSourceNodes
    t.sinkNodes = tar.getSinkNodes

    val apk = yard.getApks.head._2
    val uiRefIds: Set[String] = getCCIDSet(apk.model.getUirefUriCC())

    if(uiRefIds.size ==0){

      //MOD:SAMIN run the analysis without UiRef filtering if no ID found
      println("No UiRef CC list available")
      null
    }
    else{

      println("Running Analysis with UiRef CC filtering")
      t.sourceNodes = tar.getSourceNodes.filter { sn =>
        sn.node.node match {
          case cn :ICFGCallNode =>
            var flag = false
            yard.getApk(cn.getContext.application) match {
              case Some(apk) =>

                try {
                  val callerProc = apk.getMethod(cn.getOwner).get
                  val calleeSig = sn.descriptor.desc
                  if (calleeSig == AndroidConstants.ACTIVITY_FINDVIEWBYID || calleeSig == AndroidConstants.VIEW_FINDVIEWBYID) {

                    val callerLoc = callerProc.getBody.resolvedBody.locations(cn.locIndex)
                    val cs = callerLoc.statement.asInstanceOf[CallStatement]
                    val nums = ExplicitValueFinder.findExplicitLiteralForArgs(callerProc, callerLoc, cs.arg(0))
                    val control: LayoutControl = apk.model.getLayoutControls.get(nums.head.getInt).head
                    val widgetId: String = control.id.toString
                    flag = uiRefIds.contains(widgetId)
                  }
                  else if(relevantSources.contains(calleeSig)){
                    flag = true
                  }
                } catch {
                  case _:Throwable => false
                }

              case _ =>
            }
            flag
          case _ => false
        }
      }.toSet
      println("Source filtered")

      t.sinkNodes = tar.getSinkNodes.filter { sn =>

        sn.node.node match {
          case cn :ICFGCallNode =>
            var flag = false
            yard.getApk(cn.getContext.application) match {
              case Some(apk) =>

                try {
                  val callerProc = apk.getMethod(cn.getOwner).get
                  val calleeSig = cn.getCalleeSig
                  if(ccDisplayMethods.contains(calleeSig.signature)){
                    flag =true
                  }
                  else flag =false

                } catch {
                  case _:Throwable => false
                }

              case _ =>
            }
            flag
          case _ => false
        }

      }.toSet
      println("Sinks filtered")
      //writeResult(yard.getApks.head._2,t)
      t

    }

  }

  private def getCCIDSet(fileName: String): Set[String] = {

    val ids = new ArrayBuffer[String]()
    try {
      val source = Source.fromFile(fileName)

      for (line <- source.getLines()) {
        ids.append(line)
      }
      source.close
    }catch {
      case _:Throwable=> println("Cannot load UIREF file")
    }
    ids.toSet
  }

  def removeUnnecessaryPathsFromUISource(completeTar:TaintAnalysisResult, maskingTar:TaintAnalysisResult, yard: ApkYard): ISet[TaintPath]={

    val apk = yard.getApks.head._2

    val maskedPaths = new ArrayBuffer[TaintPath]()
    val maskingTarPaths = maskingTar.getTaintedPaths
    val completeTarPaths = completeTar.getTaintedPaths
    for(path <- maskingTarPaths){
      val src = path.getSource
      //If source is findViewById we check if the widget of the textview is same as this one
      if(src.descriptor.desc == AndroidConstants.ACTIVITY_FINDVIEWBYID || src.descriptor.desc  == AndroidConstants.VIEW_FINDVIEWBYID){
        val ccgetSourceID = findResourceId(yard,src)
        val snk = path. getSink

        for(p <- completeTarPaths){
          val s = p.getSource
          val d = p.getSink
          if(d == snk && (s.descriptor.desc == AndroidConstants.ACTIVITY_FINDVIEWBYID || s.descriptor.desc == AndroidConstants.VIEW_FINDVIEWBYID) ){

            val ccsetSourceID = findResourceId(yard,s)
            if(ccsetSourceID != ccgetSourceID ){
              maskedPaths.append(path)
            }
          }
        }
      }
      //If the source is network we just test the path if it has masked subroutine so we add it here anyway
      else{
        maskedPaths.append(path)
      }


    }
    return maskedPaths.toSet
  }

  def findResourceId (yard: ApkYard, sn :TaintSource): String = {
    var result = ""
    sn.node.node match{
      case cn :ICFGCallNode =>
        yard.getApk(cn.getContext.application) match {
          case Some(apk) =>

            try {
              val callerProc = apk.getMethod(cn.getOwner).get
              val calleeSig = sn.descriptor.desc
              if (calleeSig == AndroidConstants.ACTIVITY_FINDVIEWBYID || calleeSig == AndroidConstants.VIEW_FINDVIEWBYID) {

                val callerLoc = callerProc.getBody.resolvedBody.locations(cn.locIndex)
                val cs = callerLoc.statement.asInstanceOf[CallStatement]
                val nums = ExplicitValueFinder.findExplicitLiteralForArgs(callerProc, callerLoc, cs.arg(0))
                val control: LayoutControl = apk.model.getLayoutControls.get(nums.head.getInt).head
                val result: String = control.id.toString
                return result
              }
            } catch {
              case _:Throwable => return ""
            }

          case _ =>
        }
      case _ =>
    }

    return result
  }

  def isMasked (tps: ISet[TaintPath]): ISet[TaintPath] ={


    var results : ISet[TaintPath] = scala.collection.immutable.Set.empty[TaintPath]

    for(tp<-tps){
      var sanitized = false
      for(cm<-maskingMethods){
        if(intermediateMethodExists(tp,cm)){
          sanitized = true
        }
      }
      if(!sanitized) {
        results +=tp
      }
    }
    results
  }

  def intermediateMethodExists (tp:TaintPath, signature: String): Boolean={

    for(n <- tp.getPath){
      try{
        val method = n.node.propertyMap.get("callee_sig").get.asInstanceOf[Signature].methodName
        if(method.toString().equalsIgnoreCase(signature)) {
          return true
        }
      }catch {
        case e:Exception=>{

        }
      }


    }
    return false
  }

}
