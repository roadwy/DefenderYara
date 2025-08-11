
rule Trojan_Win32_SusRegSvr_MK{
	meta:
		description = "Trojan:Win32/SusRegSvr.MK,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 2f 00 75 00 20 00 2f 00 73 00 } //1 regsvr32.exe /u /s
		$a_00_1 = {70 00 68 00 6f 00 6e 00 65 00 68 00 6f 00 6d 00 65 00 } //1 phonehome
		$a_00_2 = {61 00 61 00 30 00 36 00 65 00 33 00 39 00 65 00 2d 00 37 00 38 00 37 00 36 00 2d 00 34 00 62 00 61 00 33 00 2d 00 62 00 65 00 65 00 65 00 2d 00 34 00 32 00 62 00 64 00 38 00 30 00 66 00 66 00 33 00 36 00 33 00 65 00 } //-1 aa06e39e-7876-4ba3-beee-42bd80ff363e
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*-1) >=2
 
}
rule Trojan_Win32_SusRegSvr_MK_2{
	meta:
		description = "Trojan:Win32/SusRegSvr.MK,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 2f 00 75 00 20 00 2f 00 73 00 } //1 regsvr32.exe /u /s
		$a_00_1 = {70 00 68 00 6f 00 6e 00 65 00 68 00 6f 00 6d 00 65 00 } //1 phonehome
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}