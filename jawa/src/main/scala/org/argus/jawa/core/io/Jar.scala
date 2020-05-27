/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.io

import java.io.{DataOutputStream, InputStream, OutputStream}
import java.util.jar._

import scala.collection.JavaConverters._
import Attributes.Name

import scala.collection.mutable
import scala.language.{implicitConversions, postfixOps}

class Jar(file: File) extends Iterable[JarEntry] {
  def this(jfile: JFile) = this(File(jfile))
  def this(path: String) = this(File(path))

  lazy val manifest: Option[JManifest] = withJarInput(s => Option(s.getManifest))

  def mainClass: Option[String] = manifest map (f => f(Name.MAIN_CLASS))
  /** The manifest-defined classpath String if available. */
  def classPathString: Option[String] =
    for (m <- manifest ; cp <- m.attrs get Name.CLASS_PATH) yield cp
  def classPathElements: List[String] = classPathString match {
    case Some(s)  => s split "\\s+" toList
    case _        => Nil
  }

  /** Invoke f with input for named jar entry (or None). */
  def withEntryStream[A](name: String)(f: Option[InputStream] => A): A = {
    val jarFile = new JarFile(file.jfile)
    def apply() =
      jarFile getEntry name match {
        case null   => f(None)
        case entry  =>
          val in = Some(jarFile getInputStream entry)
          try f(in)
          finally in foreach (_.close())
      }
    try apply() finally jarFile.close()
  }

  def withJarInput[T](f: JarInputStream => T): T = {
    val in = new JarInputStream(file.inputStream())
    try f(in)
    finally in.close()
  }
  def jarWriter(mainAttrs: (Attributes.Name, String)*): JarWriter = {
    new JarWriter(file, Jar.WManifest(mainAttrs: _*).underlying)
  }

  override def foreach[U](f: JarEntry => U): Unit = withJarInput { in =>
    Iterator continually in.getNextJarEntry takeWhile (_ != null) foreach f
  }
  override def iterator: Iterator[JarEntry] = this.toList.iterator
  override def toString: String = "" + file
}

class JarWriter(val file: File, val manifest: Manifest) {
  private lazy val out = new JarOutputStream(file.outputStream(), manifest)

  /** Adds a jar entry for the given path and returns an output
   *  stream to which the data should immediately be written.
   *  This unusual interface exists to work with fjbg.
   */
  def newOutputStream(path: String): DataOutputStream = {
    val entry = new JarEntry(path)
    out putNextEntry entry
    new DataOutputStream(out)
  }

  def writeAllFrom(dir: Directory) {
    try dir.list foreach (x => addEntry(x, ""))
    finally out.close()
  }
  def addStream(entry: JarEntry, in: InputStream) {
    out putNextEntry entry
    try transfer(in, out)
    finally out.closeEntry()
  }
  def addFile(file: File, prefix: String) {
    val entry = new JarEntry(prefix + file.name)
    addStream(entry, file.inputStream())
  }
  def addEntry(entry: Path, prefix: String) {
    if (entry.isFile) addFile(entry.toFile, prefix)
    else addDirectory(entry.toDirectory, prefix + entry.name + "/")
  }
  def addDirectory(entry: Directory, prefix: String) {
    entry.list foreach (p => addEntry(p, prefix))
  }

  private def transfer(in: InputStream, out: OutputStream): Unit = {
    val buf = new Array[Byte](10240)
    def loop(): Unit = in.read(buf, 0, buf.length) match {
      case -1 => in.close()
      case n  => out.write(buf, 0, n) ; loop()
    }
    loop()
  }

  def close(): Unit = out.close()
}

object Jar {
  type AttributeMap = java.util.Map[Attributes.Name, String]

  object WManifest {
    def apply(mainAttrs: (Attributes.Name, String)*): WManifest = {
      val m = WManifest(new JManifest)
      for ((k, v) <- mainAttrs)
        m(k) = v

      m
    }
    def apply(manifest: JManifest): WManifest = new WManifest(manifest)
  }
  class WManifest(manifest: JManifest) {
    for ((k, v) <- initialMainAttrs)
      this(k) = v

    def underlying: JManifest = manifest
    def attrs: mutable.Map[Name, String] = manifest.getMainAttributes.asInstanceOf[AttributeMap].asScala withDefaultValue null
    def initialMainAttrs: Map[Attributes.Name, String] = {
      import scala.util.Properties._
      Map(
        Name.MANIFEST_VERSION -> "1.0",
        ScalaCompilerVersion  -> versionNumberString
      )
    }

    def apply(name: Attributes.Name): String        = attrs(name)
    def update(key: Attributes.Name, value: String): Option[String] = attrs.put(key, value)
  }

  // See http://download.java.net/jdk7/docs/api/java/nio/file/Path.html
  // for some ideas.
  private val ZipMagicNumber = List[Byte](80, 75, 3, 4)
  private def magicNumberIsZip(f: Path) = f.isFile && (f.toFile.bytes().take(4).toList == ZipMagicNumber)

  def isJarOrZip(f: Path): Boolean = isJarOrZip(f, examineFile = true)
  def isJarOrZip(f: Path, examineFile: Boolean): Boolean =
    f.hasExtension("zip", "jar") || (examineFile && magicNumberIsZip(f))

  def create(file: File, sourceDir: Directory, mainClass: String) {
    val writer = new Jar(file).jarWriter(Name.MAIN_CLASS -> mainClass)
    writer writeAllFrom sourceDir
  }
}
