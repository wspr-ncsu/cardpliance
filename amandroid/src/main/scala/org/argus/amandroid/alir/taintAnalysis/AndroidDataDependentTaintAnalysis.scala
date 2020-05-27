/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.alir.taintAnalysis

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.pta.model.InterComponentCommunicationModel
import org.argus.amandroid.core.AndroidConstants
import org.argus.amandroid.core.parser.LayoutControl
import org.argus.amandroid.core.security.AndroidProblemCategories
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.flow.cfg.{ICFGCallNode, ICFGNode}
import org.argus.jawa.flow.dda.{DataDependenceBaseGraph, IDDGCallArgNode, InterProceduralDataDependenceAnalysis, InterProceduralDataDependenceInfo}
import org.argus.jawa.flow.pta.{PTAResult, VarSlot}
import org.argus.jawa.flow.taintAnalysis._
import org.argus.jawa.core.util._
import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.flow.util.ExplicitValueFinder

import scala.collection.mutable.ArrayBuffer
import scala.io.Source
import scala.collection.mutable.Queue
import scala.util.control.Breaks._
/**
 * @author <a href="mailto:fgwei521@gmail.com">Fengguo Wei</a>
 * @author <a href="mailto:sroy@k-state.edu">Sankardas Roy</a>
 */ 
object AndroidDataDependentTaintAnalysis {
  final val TITLE = "AndroidDataDependentTaintAnalysis"

  private final val relevantSources: ISet[String] = Set(

    "Ljava/net/URL;.<init>:(Ljava/lang/String;)V",
    "Landroid/content/SharedPreferences;.getString:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
    "Landroid/content/SharedPreferences?;.getString:(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
    "Ljava/net/URLConnection;.getInputStream:()Ljava/io/InputStream;",
    "Landroid/content/Intent;.<init>:(Ljava/lang/String;)V"

  )

  private final val relevantSinks: ISet[String] = Set(

    "Landroid/widget/TextView;.setText:(Ljava/lang/CharSequence;)V"

  )

  private final val implicitintentSinks: ISet[String] = Set(

    "Landroid/content/Intent;.putExtra:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;"

  )

  case class Tp(path: IList[InterProceduralDataDependenceAnalysis.Edge]) extends TaintPath {
    var srcN: TaintSource = _
    var sinN: TaintSink = _
    val typs: MSet[String] = msetEmpty
    def getSource: TaintSource = srcN
    def getSink: TaintSink = sinN
    def getTypes: ISet[String] = this.typs.toSet
    def getPath: IList[TaintNode] = {
      val list: MList[TaintNode] = mlistEmpty
      val rpath = path.reverse
      rpath.headOption match {
        case Some(head) =>
          list += TaintNode(head.target.getICFGNode, head.target.getPosition.map(new SSPosition(_)))
        case None =>
      }
      rpath.foreach { edge =>
        list += TaintNode(edge.source.getICFGNode, edge.source.getPosition.map(new SSPosition(_)))
      }
      list.toList
    }
    override def toString: String = {
      val sb = new StringBuilder
      sb.append("Taint path: ")
      this.typs foreach (typ => sb.append(typ + " "))
      sb.append("\n")
      sb.append(srcN.descriptor + "\n\t-> " + sinN.descriptor + "\n")
      path.reverse.foreach{ edge =>
        sb.append(edge.target + "\n\t-> ")
      }
      sb.append(path.head.source + "\n")
      sb.toString().intern
    }
  }
  
  class TarApk extends TaintAnalysisResult {
    var tars: MSet[TaintAnalysisResult] = msetEmpty
    def getSourceNodes: ISet[TaintSource] = tars.map(_.getSourceNodes).fold(isetEmpty)(_ ++ _)
    def getSinkNodes: ISet[TaintSink] = tars.map(_.getSinkNodes).fold(isetEmpty)(_ ++ _)
    def getTaintedPaths: ISet[TaintPath] = tars.map(_.getTaintedPaths).fold(isetEmpty)(_ ++ _)
  }
  
  case class Tar(iddi: InterProceduralDataDependenceInfo) extends TaintAnalysisResult {
    var sourceNodes: ISet[TaintSource] = isetEmpty
    var sinkNodes: ISet[TaintSink] = isetEmpty
    def getSourceNodes: ISet[TaintSource] = this.sourceNodes
    def getSinkNodes: ISet[TaintSink] = this.sinkNodes
    def getTaintedPaths: ISet[TaintPath] = {
      var tps: ISet[TaintPath] = isetEmpty
      sinkNodes.foreach { sinN =>
        sourceNodes.foreach { srcN =>
          val path = iddi.getDependentPath(iddi.getIddg.getNode(sinN.node.node, sinN.node.pos.map(p => p.pos)), iddi.getIddg.getNode(srcN.node.node, srcN.node.pos.map(p => p.pos)))
          if(path.nonEmpty) {
            val tp = Tp(path)
            tp.srcN = srcN
            tp.sinN = sinN
            val srcTyp = srcN.descriptor.typ
            val sinTyp = sinN.descriptor.typ
            if(srcTyp == SourceAndSinkCategory.API_SOURCE || srcTyp == SourceAndSinkCategory.CALLBACK_SOURCE) {
              if(sinTyp == SourceAndSinkCategory.API_SINK) tp.typs += AndroidProblemCategories.MAL_INFORMATION_LEAK
            } else if(srcTyp == SourceAndSinkCategory.ENTRYPOINT_SOURCE) {
              if(sinTyp == SourceAndSinkCategory.API_SINK) tp.typs += AndroidProblemCategories.VUL_CAPABILITY_LEAK
            } else if(srcTyp == SourceAndSinkCategory.STMT_SOURCE){
              if(sinTyp == SourceAndSinkCategory.API_SINK) tp.typs += AndroidProblemCategories.VUL_CAPABILITY_LEAK
            }
            if(tp.typs.nonEmpty) {
              tps += tp
            }
          }
        }
      }
      tps
    }
    
    override def toString: String = {
      val sb = new StringBuilder
      val paths = getTaintedPaths
      if(paths.nonEmpty) {
        getTaintedPaths.foreach(tp => sb.append(tp.toString) + "\n")
      }
      sb.toString.intern()
    }
  }
    
  def apply(yard: ApkYard, iddi: InterProceduralDataDependenceInfo, ptaresult: PTAResult, ssm: AndroidSourceAndSinkManager): TaintAnalysisResult
    = build(yard, iddi, ptaresult, ssm)
  
  def build(yard: ApkYard, iddi: InterProceduralDataDependenceInfo, ptaresult: PTAResult, ssm: AndroidSourceAndSinkManager): TaintAnalysisResult = {
    val sourceNodes: MSet[TaintSource] = msetEmpty
    val sinkNodes: MSet[TaintSink] = msetEmpty
    val uiRefCCIds: Set[String] = getIDSet(yard.getApks.head._2.model.getUirefUriCC())
    val uiRefCVCIds: Set[String] = getIDSet(yard.getApks.head._2.model.getUirefUriCVC())
    val displayWidgetIds: Set[String] = getIDSet(yard.getApks.head._2.model.getDisplayWidget())
    val iddg = iddi.getIddg
    iddg.nodes.foreach { node =>
      yard.getApk(node.getContext.application) match {
        case Some(apk) =>
          val (src, sin) = ssm.getSourceAndSinkNode(apk, node.getICFGNode, node.getPosition, ptaresult)
          sourceNodes ++= src
          sinkNodes ++= sin
        case _ =>
      }
    }
    sinkNodes foreach { sinkNode =>
      sinkNode.node.node match {
        case icfgNode: ICFGCallNode =>
          iddg.getNode(icfgNode, sinkNode.node.pos.map(p => p.pos)) match {
            case iddgNode: IDDGCallArgNode =>
              extendIDDGForSinkApis(iddg, iddgNode, ptaresult)
            case _ =>
          }
        case _ =>
      }
    }
    val tar = Tar(iddi)

    tar.sourceNodes = sourceNodes.filter { sn =>
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
                  if(uiRefCCIds!=null){
                    flag = uiRefCCIds.contains(widgetId)
                  }
                  if(uiRefCVCIds!=null && !flag){
                    flag = uiRefCVCIds.contains(widgetId)
                  }
                  //flag = true

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
    println("Source filtered for Widget IDS before running Analyzer")

    tar.sinkNodes = sinkNodes.filter { sn =>
      sn.node.node match {
        case cn: ICFGCallNode =>
          var flag = true
          yard.getApk(cn.getContext.application) match {
            case Some(apk) =>
              val calleeSig = sn.descriptor.desc
              if(relevantSinks.contains(calleeSig))
              {

                flag = false
                try{

                  val node = iddi.getIddg.getNode(sn.node.node, sn.node.pos.map(p => p.pos))
                  val queue: Queue[InterProceduralDataDependenceAnalysis.Node] = Queue(node)
                  var counter = 0
                  var continue = true

                  breakable{

                    while (queue.nonEmpty && continue){

                      //keep a depth count so it doesnt get into infinity loop
                      counter +=1
                      if(counter>50)continue = false

                      val n = queue.dequeue()
                      val s = iddg.successors(n)
                      for(nd<-s){
                        queue += nd
                      }
                      try{

                        val cnode = iddi.getIddg.getNode(n)
                        cnode.getICFGNode match{
                          case c2n: ICFGCallNode =>{

                            val method = c2n.getCalleeSig.methodName
                            if (method == "findViewById") {
                              val callerProc = apk.getMethod(c2n.getOwner).get
                              val callerLoc = callerProc.getBody.resolvedBody.locations(c2n.locIndex)
                              val cs = callerLoc.statement.asInstanceOf[CallStatement]
                              val nums = ExplicitValueFinder.findExplicitLiteralForArgs(callerProc, callerLoc, cs.arg(0))
                              val control: LayoutControl = apk.model.getLayoutControls.get(nums.head.getInt).head
                              val widgetId: String = control.id.toString
                              if(displayWidgetIds.contains(widgetId)){
                                flag = true
                                continue = false
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

              if(implicitintentSinks.contains(calleeSig))
              {

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
                      val s = iddg.icfg.predecessors(n)
                      for(nd<-s){
                        queue += nd
                      }
                      try{

                        n match{
                          case c2n: ICFGCallNode =>{

                            val method = c2n.getCalleeSig.signature
                            if (method == "Landroid/content/Intent;.<init>:(Ljava/lang/String;)V") {
                              val callerProc = apk.getMethod(c2n.getOwner).get
                              val callerLoc = callerProc.getBody.resolvedBody.locations(c2n.locIndex)
                              val cs = callerLoc.statement.asInstanceOf[CallStatement]
                              val nums = ExplicitValueFinder.findExplicitLiteralForArgs(callerProc, callerLoc, cs.arg(0))
                              val intentType = nums.head.getString
                              if(intentType == "android.intent.action.SEND"){
                                flag = true
                                continue = false
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

              if(InterComponentCommunicationModel.isIccOperation(cn.getCalleeSig)) {
                flag = ssm.isIntentSink(apk, cn, sn.node.pos.map(p => p.pos), ptaresult)
              }
            case _ =>
          }
          flag
        case _ => true
      }
    }.toSet
    val tps = tar.getTaintedPaths
    if(tps.nonEmpty) {
      System.err.println(TITLE + " found " + tps.size + s" path${if(tps.size > 1)"s" else ""}.")
      System.err.println(tar.toString)
    }
    tar
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
      case _:Throwable=> println("Cannot load UIREF file")
    }
    ids.toSet
  }
  
  private def extendIDDGForSinkApis(iddg: DataDependenceBaseGraph[InterProceduralDataDependenceAnalysis.Node], callArgNode: IDDGCallArgNode, ptaresult: PTAResult): Unit = {
    val argSlot = VarSlot(callArgNode.argName)
    val argValue = ptaresult.pointsToSet(callArgNode.getContext, argSlot)
    val argRelatedValue = ptaresult.getRelatedHeapInstances(callArgNode.getContext, argValue)
    argRelatedValue.foreach{ ins =>
      if(ins.defSite != callArgNode.getContext) {
        iddg.findDefSite(ins.defSite) match {
          case Some(t) => iddg.addEdge(callArgNode, t)
          case None =>
        }
      }
    }
  }
}