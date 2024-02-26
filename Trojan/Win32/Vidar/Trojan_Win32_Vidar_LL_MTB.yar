
rule Trojan_Win32_Vidar_LL_MTB{
	meta:
		description = "Trojan:Win32/Vidar.LL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d0 8b f8 c1 ea 05 c1 e7 04 03 fb 03 d5 33 d7 8b 7c 24 10 03 f8 33 d7 2b f2 } //00 00 
	condition:
		any of ($a_*)
 
}