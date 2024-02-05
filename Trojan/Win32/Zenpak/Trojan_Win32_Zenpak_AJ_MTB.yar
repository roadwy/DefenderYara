
rule Trojan_Win32_Zenpak_AJ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 44 24 64 b9 6d 78 29 cc 89 44 24 1c f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 1c 29 c1 83 e9 05 89 4c 24 18 75 } //00 00 
	condition:
		any of ($a_*)
 
}