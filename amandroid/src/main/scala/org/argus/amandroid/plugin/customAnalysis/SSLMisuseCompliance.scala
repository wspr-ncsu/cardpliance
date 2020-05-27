/*
 * Copyright (c) 2019. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.plugin.customAnalysis

import java.io.{File, PrintWriter}

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.componentSummary.ComponentBasedAnalysis.TITLE
import org.argus.amandroid.alir.dataRecorder.DataCollector
import org.argus.amandroid.alir.taintAnalysis.{AndroidDataDependentTaintAnalysis, AndroidSourceAndSinkManager}
import org.argus.amandroid.alir.taintAnalysis.AndroidDataDependentTaintAnalysis.{TITLE, Tar, implicitintentSinks}
import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.{AndroidConstants, AndroidGlobalConfig, ApkGlobal}
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.amandroid.core.parser.LayoutControl
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.amandroid.plugin.ApiMisuseModules
import org.argus.amandroid.plugin.apiMisuse.{CryptographicMisuse, HideIcon, SSLTLSMisuse}
import org.argus.jawa.core.ast.{CallStatement, LiteralExpression}
import org.argus.jawa.core.elements.{JawaType, Signature}
import org.argus.jawa.core.io.{FileReporter, MsgLevel, NoReporter}
import org.argus.jawa.core.util._
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.cfg.{ICFGCallNode, ICFGInvokeNode, ICFGNode}
import org.argus.jawa.flow.dda.{DataDependenceBaseGraph, IDDGNode, InterProceduralDataDependenceAnalysis, InterProceduralDataDependenceInfo}
import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.flow.pta.{PTAConcreteStringInstance, VarSlot}
import org.argus.jawa.flow.pta.suspark.InterProceduralSuperSpark
import org.argus.jawa.flow.taintAnalysis.{TaintAnalysisResult, TaintPath, TaintSink}
import org.argus.jawa.flow.util.ExplicitValueFinder
import org.jgrapht.traverse.BreadthFirstIterator

import scala.collection.mutable
import scala.collection.mutable.{ArrayBuffer, Queue}
import scala.io.Source
import scala.util.control.Breaks.breakable

/**
  * @project argus-saf
  * @author samin on 3/29/19
  */
class SSLMisuseCompliance {

  private final val networkSink: ISet[String] = Set(

    "Ljava/io/OutputStreamWriter;.write:(Ljava/lang/String;)V",
    "Ljava/io/OutputStream;.write:([B)V",
    "Ljava/io/OutputStream;.write:([BII)V",
    "Ljava/io/OutputStream;.write:(I)V"

  )

  private var backtrackNode: ICFGCallNode = null
  private var sslMisuse = false
  private var sslMisuseResult : String  = null
  private var httpExists = false
  private var urlSetasString : String  = ""
  private var urlSet: mutable.MutableList[String] =mutable.MutableList()

  val problematicComp: MMap[FileResourceUri, MSet[JawaType]] = mmapEmpty

  def sslMisusecheck(iddResult: (ISet[ApkGlobal], InterProceduralDataDependenceInfo),yard: ApkYard): Unit ={

    apply(ApiMisuseModules.SSLTLS_MISUSE, false, yard.getApks.head._2.model.getsourcePath(), yard.getApks.head._2.model.getoutputPath(), false, false)

  }

  def apply(module: ApiMisuseModules.Value, debug: Boolean, sourcePath: String, outputPath: String, forceDelete: Boolean, guessPackage: Boolean) {
    val apkFileUris: MSet[FileResourceUri] = msetEmpty
    val fileOrDir = new File(sourcePath)
    fileOrDir match {
      case dir if dir.isDirectory =>
        apkFileUris ++= ApkFileUtil.getApks(FileUtil.toUri(dir))
      case file =>
        if(ApkGlobal.isValidApk(FileUtil.toUri(file)))
          apkFileUris += FileUtil.toUri(file)
        else println(file + " is not decompilable.")
    }

    apiMisuse(apkFileUris.toSet, outputPath, module, debug, forceDelete, guessPackage)
  }

  def apiMisuse(apkFileUris: Set[FileResourceUri], outputPath: String, module: ApiMisuseModules.Value, debug: Boolean, forceDelete: Boolean, guessPackage: Boolean): Unit = {
    Context.init_context_length(AndroidGlobalConfig.settings.k_context)

    println("Total apks: " + apkFileUris.size)

    try{
      var i: Int = 0
      apkFileUris.foreach{ fileUri =>
        i += 1
        try{
          println("Analyzing #" + i + ":" + fileUri)
          val reporter =
            if(debug) new FileReporter(outputPath, MsgLevel.INFO)
            else new NoReporter
          val yard = new ApkYard(reporter)
          val outputUri = FileUtil.toUri(outputPath)
          val layout = DecompileLayout(outputUri)
          val strategy = DecompileStrategy(layout)
          val settings = DecompilerSettings(debugMode = false, forceDelete = forceDelete, strategy, reporter)
          val apk = yard.loadApk(fileUri, settings, collectInfo = false, resolveCallBack = false)
          val (checker, buildIDFG) = module match {
            case ApiMisuseModules.SSLTLS_MISUSE => (new SSLTLSMisuse, false)
          }
          if(buildIDFG) {
            AppInfoCollector.collectInfo(apk, resolveCallBack = true, guessPackage)
            apk.model.getComponents foreach { comp =>
              val clazz = apk.getClassOrResolve(comp)
              val spark = new InterProceduralSuperSpark(apk)
              val idfg = spark.build(clazz.getDeclaredMethods.map(_.getSignature))
              val res = checker.check(apk, Some(idfg))
              sslMisuseResult = res.toString
              if(res.misusedApis.size>0){
                sslMisuse = true

              }
              println(res.toString)
            }
          } else {
            val res = checker.check(apk, None)
            println(res.toString)
            sslMisuseResult = res.toString
            if(res.misusedApis.size>0) {
              sslMisuse = true

            }
            //writeResult(res.toString,outputUri,fileUri)
          }
          if(debug) println("Debug info write into " + reporter.asInstanceOf[FileReporter].f)
        } catch {
          case _: IgnoreException => println("No interested api found.")
          case e: Throwable =>
            println("Error: "+e)
        }
      }
    } catch {
      case e: Throwable =>
        println("Error: "+e)

    }
  }

  def getSSLMisuse : Boolean ={
    sslMisuse
  }

  def getHTTPExists : Boolean ={
    httpExists
  }

  def getSSLMisuseResult : String ={
    sslMisuseResult
  }

  def getUrlSet : String ={
    urlSetasString
  }


  private def getIDSet(fileName: String): Set[String] = {

    val ids = new ArrayBuffer[String]()
    try {
      val source = Source.fromFile(fileName)

      for (line <- source.getLines()) {
        ids.append(line)
      }
      source.close
    }catch {
      case _:Throwable => println("Cannot load UIREF file")
    }
    ids.toSet
  }

  def filterSourceSinks(iddResult: (ISet[ApkGlobal], InterProceduralDataDependenceInfo), tar:TaintAnalysisResult, yard: ApkYard): Tar ={

    var t = new Tar(iddResult._2)
    t.sourceNodes = tar.getSourceNodes
    t.sinkNodes = tar.getSinkNodes

    val apk = yard.getApks.head._2
    val uiRefIds: Set[String] = getIDSet(apk.model.getUirefUriCC())
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
              } catch {
                case _:Throwable => false
              }

            case _ =>
          }
          flag
        case _ => false
      }
    }.toSet

    t.sinkNodes = tar.getSinkNodes.filter { sn =>

      sn.node.node match {
        case cn :ICFGCallNode =>
          var flag = false
          yard.getApk(cn.getContext.application) match {
            case Some(apk) =>

              try {
                val callerProc = apk.getMethod(cn.getOwner).get
                val calleeSig = cn.getCalleeSig
                if(networkSink.contains(calleeSig.signature)){

                  flag = false

                  try{

                    val queue: Queue[ICFGNode] = Queue(cn)
                    var counter = 0
                    var continue = true

                    breakable{

                      while (queue.nonEmpty && continue){

                        //keep a depth count so it doesnt get into infinity loop
                        counter +=1
                        if(counter>50)continue = false

                        val n = queue.dequeue()
                        val s = iddResult._2.getIddg.icfg.predecessors(n)
                        for(nd<-s){
                          queue += nd
                        }
                        try{

                          n match{
                            case c2n: ICFGCallNode =>{

                              val method = c2n.getCalleeSig.signature
                              if (method == "Ljava/net/URL;.<init>:(Ljava/lang/String;)V") {
                                val callerProc = apk.getMethod(c2n.getOwner).get
                                val callerLoc = callerProc.getBody.resolvedBody.locations(c2n.locIndex)
                                val cs = callerLoc.statement.asInstanceOf[CallStatement]
                                val nums = ExplicitValueFinder.findExplicitLiteralForArgs(callerProc, callerLoc, cs.arg(0)) map{
                                  case str : LiteralExpression => {
                                    val s =str.constant.rawText
                                    //somehow extra quotation is added on string
                                    urlSet +=s.substring(1,s.length-1)
                                  }
                                  case _=> "ANY"
                                }

                                for(urlvalue <- urlSet) {
                                  if (!urlvalue.equalsIgnoreCase("ANY")) {
                                    urlSetasString += urlvalue + "\n"
                                    println(urlvalue)
                                    if (urlvalue.slice(0, 4).equalsIgnoreCase("http") && !urlvalue.slice(0, 5).equalsIgnoreCase("https")) {
                                      httpExists = true
                                      flag = true
                                      continue = false

                                    }

                                  }
                                }


                              }

                            }

                          }

                        }catch {
                          case _=>
                        }
                      }

                    }

                  }

                  catch {
                    case _=>
                  }



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
    t

  }


  def getPathsForInsecureEgress(completeTar:TaintAnalysisResult, egressTar:TaintAnalysisResult, yard: ApkYard): ISet[TaintPath]={

    //val ccDisplayIds: Set[String] = Set("21311653211")
    val apk = yard.getApks.head._2

    val egressPaths = new ArrayBuffer[TaintPath]()
    val egressTarPaths = egressTar.getTaintedPaths
    val completeTarPaths = completeTar.getTaintedPaths
    for(path <- egressTarPaths){
      val src = path.getSource
      val snk = path. getSink

      for(p <- completeTarPaths){
        val s = p.getSource
        val d = p.getSink
        var sd = d.descriptor.desc
        var dd = snk.descriptor.desc
        if(d.descriptor.desc == snk.descriptor.desc && (s.descriptor.desc == "Ljava/net/URL;.<init>:(Ljava/lang/String;)V" ) ){
          egressPaths.append(path)

          s.node.node match {
            case cn : ICFGCallNode =>{

              val callerProc = apk.getMethod(cn.getOwner).get
              val callerLoc = callerProc.getBody.resolvedBody.locations(cn.locIndex)
              val cs = callerLoc.statement.asInstanceOf[CallStatement]
              val nums = ExplicitValueFinder.findExplicitLiteralForArgs(callerProc, callerLoc, cs.arg(0)) map{
                case str : LiteralExpression => {
                  val s =str.constant.rawText
                  //somehow extra quotation is added on string
                  urlSet +=s.substring(1,s.length-1)
                }
                case _=> "ANY"
              }

            }

          }

        }
      }

    }

    for(urlvalue <- urlSet) {
      if (!urlvalue.equalsIgnoreCase("ANY")) {
        urlSetasString += urlvalue + "\n"
        println(urlvalue)
        if (urlvalue.slice(0, 4).equalsIgnoreCase("http") && !urlvalue.slice(0, 5).equalsIgnoreCase("https")) {
          httpExists = true

        }

      }
    }

    return egressPaths.toSet
  }

}
