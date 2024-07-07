
rule TrojanDownloader_O97M_SuspMacro_A{
	meta:
		description = "TrojanDownloader:O97M/SuspMacro.A,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //CreateObject("Microsoft.XMLHTTP")  1
		$a_80_1 = {77 72 69 74 65 } //write  1
		$a_80_2 = {73 61 76 65 74 6f 66 69 6c 65 } //savetofile  1
		$a_80_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //CreateObject("WScript.Shell")  1
		$a_80_4 = {2e 52 75 6e 28 } //.Run(  1
		$a_80_5 = {63 73 63 72 69 70 74 } //cscript  1
		$a_80_6 = {6d 6f 76 65 } //move  1
		$a_80_7 = {43 61 6c 6c } //Call  1
		$a_80_8 = {2e 53 65 6e 64 } //.Send  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}