
rule Trojan_Win32_Cridex_GGL_MTB{
	meta:
		description = "Trojan:Win32/Cridex.GGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {83 c4 18 89 45 ec 8b 75 0c 83 ee 7c 33 35 90 01 04 83 c6 22 2b 75 0c 83 c6 56 89 75 08 90 00 } //0a 00 
		$a_02_1 = {8b f8 2b 7d 18 33 3d 90 01 04 2b fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}