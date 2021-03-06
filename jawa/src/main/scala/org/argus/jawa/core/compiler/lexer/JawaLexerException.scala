/*
 * Copyright (c) 2018. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.jawa.core.compiler.lexer

import org.argus.jawa.core.compiler.parser.JawaParserException
import org.argus.jawa.core.io.Position

class JawaLexerException(pos: Position, message: String) extends JawaParserException(pos, message)
