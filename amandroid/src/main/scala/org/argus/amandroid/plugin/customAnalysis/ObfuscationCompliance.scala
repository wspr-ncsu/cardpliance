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


import org.argus.jawa.core.elements.Signature
import org.argus.jawa.core.util.ISet
import org.argus.jawa.flow.taintAnalysis.TaintPath

/**
  * @project argus-saf
  * @author samin on 4/4/19
  */
class ObfuscationCompliance {

  private final val cryptoMethods: ISet[String] = Set(


    "doFinal",
    "digest",
    "update",
    "updateAAD",
    "encrypt",
    "encode"
  )

  def isObfuscated (tps: ISet[TaintPath]): ISet[TaintPath] ={


    var results : ISet[TaintPath] = scala.collection.immutable.Set.empty[TaintPath]

    for(tp<-tps){
      var sanitized = false
      for(cm<-cryptoMethods){
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
