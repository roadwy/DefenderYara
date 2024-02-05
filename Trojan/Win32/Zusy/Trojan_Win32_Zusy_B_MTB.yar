
rule Trojan_Win32_Zusy_B_MTB{
	meta:
		description = "Trojan:Win32/Zusy.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 02 8b 56 10 8a 0c b8 2a cb 88 4d f0 3b 56 14 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_B_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 ea 18 20 00 00 89 55 e8 8b 45 ec 2d 3b 1a 00 00 89 45 ec 8b 4d e8 81 c1 c2 0e 00 00 89 4d e8 8b 55 f8 81 ea 53 23 00 00 89 55 f8 } //00 00 
	condition:
		any of ($a_*)
 
}