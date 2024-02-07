
rule Trojan_Win32_Guloader_GG_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f ef d7 81 90 02 05 c3 90 0a 99 00 ff 37 90 02 1e 31 34 24 90 02 1e 8f 04 10 90 02 52 81 fa 90 02 04 75 90 02 1e ff d0 90 00 } //01 00 
		$a_81_1 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}