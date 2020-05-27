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

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.amandroid.core.parser.LayoutControl
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util._
import org.argus.jawa.flow.Context
import org.argus.jawa.flow.cfg.ICFGCallNode
import org.argus.jawa.flow.dda.{InterProceduralDataDependenceAnalysis, InterProceduralDataDependenceInfo}
import org.argus.jawa.flow.dfa.InterProceduralDataFlowGraph
import org.argus.jawa.flow.pta.{PTAConcreteStringInstance, VarSlot}
import org.argus.jawa.flow.taintAnalysis.{TaintAnalysisResult, TaintPath}
import org.argus.jawa.flow.util.ExplicitValueFinder
import org.jgrapht.traverse.DepthFirstIterator

import scala.collection.mutable.Queue
import scala.util.control.Breaks.breakable
import scala.util.control.Exception

/**
  * @project argus-saf
  * @author samin on 4/1/19
  */
class CardplianceUtils {

  def traverseTaintedPaths (tp:TaintPath): Unit={

    try{

      for(n <- tp.getPath){
        val callee = n.node.propertyMap.get("callee_sig").get.asInstanceOf[Signature]
        println(callee.signature)

      }
      println()
    }
    catch {
      case e: Exception =>
    }

  }

  def traverseTaintedPathsWithYard (tp:TaintPath, yard: ApkYard): Unit={

    try{

      for(n <- tp.getPath){
        val callee = n.node.propertyMap.get("callee_sig").get.asInstanceOf[Signature]
        n.node match {

          case x: ICFGCallNode =>{
            findResourceId(yard,x)
          }
          case _=>

        }
        println(callee.signature)

      }
      println()
    }
    catch {
      case e: Exception =>
    }

  }

  def intermediateMethodExists (tp:TaintPath, signature: String): Boolean={

    try{
      for(n <- tp.getPath){
        val callee = n.node.propertyMap.get("callee_sig").get.asInstanceOf[Signature]
        if(callee.toString().equalsIgnoreCase(signature)) return true

      }

    }
    catch {
      case e: Exception =>
    }

    return false
  }

  def getTaintedPath (tp:TaintPath): StringBuilder={

    var string : StringBuilder = new StringBuilder
    for(n <- tp.getPath){
      try {
        val callee = n.node.propertyMap.get("callee_sig").get.asInstanceOf[Signature]
        string.append(callee.signature+"\n")

      }
      catch {
        case e: Exception =>
      }


    }

    string.append("\n")
    string
  }

  def traverseBFS (idfg: InterProceduralDataFlowGraph): Unit={

    val root = idfg.icfg.entryNode
    val it = idfg.icfg.getIterator(root)

    while (it.hasNext){

      val n = it.next();
      val s = idfg.icfg.successors(n)
      n match {
        case cn : ICFGCallNode =>{
          val s = idfg.icfg.successors(cn)
          println(cn.getCalleeSig.signature)
        }
        case _=>

      }
      print("")
    }


  }

  def matchSig (iddResult: (ISet[ApkGlobal], InterProceduralDataDependenceInfo), tar:TaintAnalysisResult, yard: ApkYard, sig: String) : String ={

    var result = "Not found";

    val idfgs = yard.getApks.head._2.getIDFGs.values
    val urlMap: MMap[Context, MSet[String]] = mmapEmpty
    for(idfg <- idfgs){

      idfg.icfg.nodes foreach {
        case cn: ICFGCallNode if cn.getCalleeSig.methodName.equalsIgnoreCase(sig) =>
          return cn.getCalleeSig.signature
        case _ =>
      }
    }

    return result

  }

  def findResourceId (yard: ApkYard, cn :ICFGCallNode): String = {
    yard.getApk(cn.getContext.application) match {
      case Some(apk) =>

        try {
          val callerProc = apk.getMethod(cn.getOwner).get
          val callerLoc = callerProc.getBody.resolvedBody.locations(cn.locIndex)
          val cs = callerLoc.statement.asInstanceOf[CallStatement]
          val nums = ExplicitValueFinder.findExplicitLiteralForArgs(callerProc, callerLoc, cs.arg(0))
          val control: LayoutControl = apk.model.getLayoutControls.get(nums.head.getInt).head
          val widgetId: String = control.id.toString
        } catch {
          case _: Throwable => false
        }

      case _ =>
    }
    return ""
  }

}
