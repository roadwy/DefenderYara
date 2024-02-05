
rule Trojan_Win32_Guloader_RPV_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPV!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 1c 08 d9 fd 0f ae e8 eb 2d } //01 00 
		$a_01_1 = {39 c6 66 0f fd c7 d9 fd eb 35 } //00 00 
	condition:
		any of ($a_*)
 
}