
rule Trojan_Win32_SusNetShare_MK{
	meta:
		description = "Trojan:Win32/SusNetShare.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 00 62 00 5f 00 } //1 sb_
		$a_00_1 = {5f 00 62 00 73 00 20 00 3e 00 6e 00 75 00 6c 00 } //1 _bs >nul
		$a_00_2 = {6e 00 65 00 74 00 20 00 73 00 68 00 61 00 72 00 65 00 20 00 26 00 20 00 65 00 78 00 69 00 74 00 } //1 net share & exit
		$a_00_3 = {61 00 61 00 30 00 36 00 65 00 33 00 39 00 65 00 2d 00 37 00 38 00 37 00 36 00 2d 00 34 00 62 00 61 00 33 00 2d 00 62 00 65 00 65 00 65 00 2d 00 34 00 32 00 62 00 64 00 38 00 30 00 66 00 66 00 33 00 36 00 32 00 61 00 } //-1 aa06e39e-7876-4ba3-beee-42bd80ff362a
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}
rule Trojan_Win32_SusNetShare_MK_2{
	meta:
		description = "Trojan:Win32/SusNetShare.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 00 62 00 5f 00 } //1 sb_
		$a_00_1 = {5f 00 62 00 73 00 20 00 3e 00 6e 00 75 00 6c 00 } //1 _bs >nul
		$a_00_2 = {6e 00 65 00 74 00 20 00 73 00 68 00 61 00 72 00 65 00 20 00 26 00 20 00 65 00 78 00 69 00 74 00 } //1 net share & exit
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}