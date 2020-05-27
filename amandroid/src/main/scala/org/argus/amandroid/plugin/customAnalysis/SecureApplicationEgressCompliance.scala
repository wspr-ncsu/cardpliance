package org.argus.amandroid.plugin.customAnalysis

/**
  * @project argus-saf
  * @author samin on 7/3/19
  */

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


class SecureApplicationEgressCompliance {

  private final val persistentStorage: ISet[String] = Set(

    "Landroid/content/Intent;.putExtra:(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
    "Landroid/telephony/SmsManager;.sendMultipartTextMessage:(Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;)V",
    "Landroid/telephony/SmsManager;.sendDataMessage:(Ljava/lang/String;Ljava/lang/String;S[BLandroid/app/PendingIntent;Landroid/app/PendingIntent;)V",
    "Landroid/telephony/SmsManager;.sendTextMessage:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V"

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
