
rule VirTool_Win32_Obfuscator_HD{
	meta:
		description = "VirTool:Win32/Obfuscator.HD,SIGNATURE_TYPE_PEHSTR,18 00 18 00 0e 00 00 "
		
	strings :
		$a_01_0 = {62 79 20 48 6f 6c 79 5f 46 61 74 68 65 72 20 26 26 20 52 61 74 74 65 72 2f 32 39 41 } //2 by Holy_Father && Ratter/29A
		$a_01_1 = {61 73 20 61 20 70 61 72 74 20 6f 66 20 54 68 65 20 48 61 63 6b 65 72 20 44 65 66 65 6e 64 65 72 20 50 72 6f 6a 65 63 74 20 2d 20 68 74 74 70 3a 2f 2f 77 77 77 2e 68 78 64 65 66 2e 6f 72 67 } //2 as a part of The Hacker Defender Project - http://www.hxdef.org
		$a_01_2 = {68 74 74 70 3a 2f 2f 68 78 64 65 66 2e 6e 65 74 2e 72 75 2c 20 68 74 74 70 3a 2f 2f 68 78 64 65 66 2e 63 7a 77 65 62 2e 6f 72 67 2c 20 68 74 74 70 3a 2f 2f 72 6f 6f 74 6b 69 74 2e 68 6f 73 74 2e 73 6b } //2 http://hxdef.net.ru, http://hxdef.czweb.org, http://rootkit.host.sk
		$a_01_3 = {43 6f 70 79 72 69 67 68 74 20 28 63 29 20 32 30 30 30 2c 66 6f 72 65 76 65 72 20 45 78 45 77 4f 52 78 } //2 Copyright (c) 2000,forever ExEwORx
		$a_01_4 = {62 65 74 61 74 65 73 74 65 64 20 62 79 20 63 68 30 70 70 65 72 20 3c 54 48 45 4d 41 53 4b 44 45 4d 4f 4e 40 66 6c 61 73 68 6d 61 69 6c 2e 63 6f 6d 3e } //2 betatested by ch0pper <THEMASKDEMON@flashmail.com>
		$a_01_5 = {62 69 72 74 68 64 61 79 3a 20 30 33 2e 31 30 2e 32 30 30 34 } //2 birthday: 03.10.2004
		$a_01_6 = {5b 2d 71 5d 20 5b 2d 64 5d 20 5b 2d 62 3a 49 6d 61 67 65 42 61 73 65 5d 20 5b 2d 6f 3a 4f 75 74 70 75 74 46 69 6c 65 5d 20 49 6e 70 75 74 46 69 6c 65 20 } //2 [-q] [-d] [-b:ImageBase] [-o:OutputFile] InputFile 
		$a_01_7 = {2d 71 20 20 20 20 20 20 20 20 20 20 20 20 20 62 65 20 71 75 69 65 74 20 28 6e 6f 20 63 6f 6e 73 6f 6c 65 20 6f 75 74 70 75 74 29 } //2 -q             be quiet (no console output)
		$a_01_8 = {2d 64 20 20 20 20 20 20 20 20 20 20 20 20 20 66 6f 72 20 64 79 6e 61 6d 69 63 20 44 4c 4c 73 20 6f 6e 6c 79 } //2 -d             for dynamic DLLs only
		$a_01_9 = {2d 69 20 20 20 20 20 20 20 20 20 20 20 20 20 73 61 76 65 20 72 65 73 6f 75 72 63 65 20 69 63 6f 6e 20 61 6e 64 20 58 50 20 6d 61 6e 69 66 65 73 74 } //2 -i             save resource icon and XP manifest
		$a_01_10 = {2d 61 20 20 20 20 20 20 20 20 20 20 20 20 20 73 61 76 65 20 6f 76 65 72 6c 61 79 20 64 61 74 61 20 66 72 6f 6d 20 74 68 65 20 65 6e 64 20 6f 66 20 6f 72 69 67 69 6e 61 6c 20 66 69 6c 65 } //2 -a             save overlay data from the end of original file
		$a_01_11 = {2d 62 3a 49 6d 61 67 65 42 61 73 65 20 20 20 73 70 65 63 69 66 79 20 69 6d 61 67 65 20 62 61 73 65 20 69 6e 20 68 65 78 61 64 65 63 69 6d 61 6c 20 73 74 72 69 6e 67 } //2 -b:ImageBase   specify image base in hexadecimal string
		$a_01_12 = {2d 6f 3a 4f 75 74 70 75 74 46 69 6c 65 20 20 73 70 65 63 69 66 79 20 66 69 6c 65 20 66 6f 72 20 6f 75 74 70 75 74 } //2 -o:OutputFile  specify file for output
		$a_01_13 = {28 49 6e 70 75 74 46 69 6c 65 20 77 69 6c 6c 20 62 65 20 72 65 77 72 69 74 74 65 6e 20 69 66 20 6e 6f 20 4f 75 74 70 75 74 46 69 6c 65 20 67 69 76 65 6e 29 } //2 (InputFile will be rewritten if no OutputFile given)
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_01_11  & 1)*2+(#a_01_12  & 1)*2+(#a_01_13  & 1)*2) >=24
 
}