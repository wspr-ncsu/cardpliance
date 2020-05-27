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

import java.io.PrintWriter

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.alir.dataRecorder.DataCollector
import org.argus.amandroid.alir.taintAnalysis.AndroidDataDependentTaintAnalysis.Tar
import org.argus.amandroid.core.{AndroidConstants, ApkGlobal}
import org.argus.amandroid.core.parser.LayoutControl
import org.argus.jawa.core.ast.CallStatement
import org.argus.jawa.core.util.{FileUtil, ISet, MSet}
import org.argus.jawa.flow.cfg.ICFGCallNode
import org.argus.jawa.flow.dda.InterProceduralDataDependenceInfo
import org.argus.jawa.flow.taintAnalysis.TaintAnalysisResult
import org.argus.jawa.flow.util.ExplicitValueFinder

import scala.collection.mutable.ArrayBuffer
import scala.io.Source

/**
  * @project argus-saf
  * @author samin on 3/6/19
  */
class CCNumberRetentionCompliance {

  private final val persistentStorage: ISet[String] = Set(

    "Landroid/util/Log;.d:(Ljava/lang/String;Ljava/lang/String;)I",
    "Landroid/util/Log;.d:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I",
    "Landroid/util/Log;.e:(Ljava/lang/String;Ljava/lang/String;)I" ,
    "Landroid/util/Log;.e:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I",
    "Landroid/util/Log;.i:(Ljava/lang/String;Ljava/lang/String;)I" ,
    "Landroid/util/Log;.i:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I" ,
    "Landroid/util/Log;.v:(Ljava/lang/String;Ljava/lang/String;)I" ,
    "Landroid/util/Log;.v:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I" ,
    "Landroid/util/Log;.w:(Ljava/lang/String;Ljava/lang/Throwable;)I" ,
    "Landroid/util/Log;.w:(Ljava/lang/String;Ljava/lang/String;)I" ,
    "Landroid/util/Log;.w:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I" ,
    "Landroid/util/Log;.wtf:(Ljava/lang/String;Ljava/lang/Throwable;)I" ,
    "Landroid/util/Log;.wtf:(Ljava/lang/String;Ljava/lang/String;)I" ,
    "Landroid/util/Log;.wtf:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I" ,

    "Ljava/io/OutputStream;.write:([B)V" ,
    "Ljava/io/OutputStream;.write:([BII)V" ,
    "Ljava/io/OutputStream;.write:(I)V" ,
    "Ljava/io/FileOutputStream;.write:([B)V" ,
    "Ljava/io/FileOutputStream;.write:([BII)V" ,
    "Ljava/io/FileOutputStream;.write:(I)V" ,
    "Ljava/io/Writer;.write:([C)V" ,
    "Ljava/io/Writer;.write:([CII)V" ,
    "Ljava/io/Writer;.write:(I)V" ,
    "Ljava/io/Writer;.write:(Ljava/lang/String;)V" ,
    "Ljava/io/Writer;.write:(Ljava/lang/String;II)V" ,

    "Landroid/content/SharedPreferences$Editor;.putBoolean:(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;",
    "Landroid/content/SharedPreferences$Editor;.putFloat:(Ljava/lang/String;F)Landroid/content/SharedPreferences$Editor;",
    "Landroid/content/SharedPreferences$Editor;.putInt:(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;",
    "Landroid/content/SharedPreferences$Editor;.putLong:(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;",
    "Landroid/content/SharedPreferences$Editor?;.putString:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
    "Landroid/content/SharedPreferences$Editor;.putString:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;"

  )

   def filterSourceSink(iddResult: (ISet[ApkGlobal], InterProceduralDataDependenceInfo), tar:TaintAnalysisResult, yard: ApkYard): Tar ={

    var t = new Tar(iddResult._2)
    t.sourceNodes = tar.getSourceNodes
    t.sinkNodes = tar.getSinkNodes

    val apk = yard.getApks.head._2
    val uiRefIds: Set[String] = getIDSet(apk.model.getUirefUriCC())

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
                  if(persistentStorage.contains(calleeSig.signature)){
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

  private def getIDSet(fileName: String): Set[String] = {

    val ids = new ArrayBuffer[String]()
    try {
      val source = Source.fromFile(fileName)

      for (line <- source.getLines()) {
        ids.append(line)
      }
      source.close
    }catch {
      case _:Throwable=> println("Cannot load UIREF CC file")
    }
    ids.toSet
  }


}
