/*******************************************************************************
 * Copyright (C) 2012..2016 norbert.klose@web.de
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS 
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/

#include <StackTrace.hpp>

void captureStackTrace(cstack::StackTrace & stackTrace)
{
	stackTrace.capture();
}

int main(int argc, char * args[])
{
	cstack::StackTrace stacktrace;
	captureStackTrace(stacktrace);
	
	std::cout << "Unformatted StackTrace:" << std::endl;
	for (std::string frame : stacktrace)
		std::cout << frame << std::endl;
	
	std::cout << std::endl
		      << "Formatted StackTrace:" << std::endl;
	std::cout << stacktrace;
}
