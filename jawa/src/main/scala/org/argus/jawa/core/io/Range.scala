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

case class Range(offset: Int, length: Int) {

  def contains(other: Range): Boolean = other.offset >= offset && other.offset + other.length <= offset + length

  def strictlyContains(other: Range): Boolean = (this contains other) && this.length > other.length

  /**
   * @return the smallest range that contains both this and other
   */
  def mergeWith(other: Range): Range = {
    val List(earliest, latest) = List(this, other) sortBy (_.offset)
    Range(earliest.offset, latest.offset - earliest.offset + latest.length)
  }

  def intersects(other: Range): Boolean =
    !(other.offset >= offset + length || other.offset + other.length - 1 < offset)

  def expandLeft(n: Int): Range = Range(offset - n, length + n)

}
