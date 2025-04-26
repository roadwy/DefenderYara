
rule Trojan_BAT_Tnega_BL_MTB{
	meta:
		description = "Trojan:BAT/Tnega.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {62 77 44 6f 77 6e 6c 6f 61 64 65 72 } //1 bwDownloader
		$a_01_1 = {24 64 33 66 61 30 38 39 38 2d 65 66 32 32 2d 34 34 39 66 2d 61 61 38 32 2d 35 66 36 62 37 66 65 36 33 63 34 32 } //1 $d3fa0898-ef22-449f-aa82-5f6b7fe63c42
		$a_01_2 = {6f 62 66 75 73 63 61 74 6f 72 42 79 74 65 73 } //1 obfuscatorBytes
		$a_01_3 = {4f 62 66 75 73 63 61 74 6f 72 } //1 Obfuscator
		$a_01_4 = {6f 00 62 00 66 00 75 00 73 00 63 00 61 00 74 00 6f 00 72 00 45 00 72 00 72 00 6f 00 72 00 4c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 } //1 obfuscatorErrorLog.txt
		$a_01_5 = {62 77 52 65 6f 62 66 75 73 63 61 74 65 } //1 bwReobfuscate
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_7 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}