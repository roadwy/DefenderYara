
rule Trojan_Win32_Guloader_GG_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f ef d7 81 [0-05] c3 90 0a 99 00 ff 37 [0-1e] 31 34 24 [0-1e] 8f 04 10 [0-52] 81 fa [0-04] 75 [0-1e] ff d0 } //1
		$a_81_1 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}