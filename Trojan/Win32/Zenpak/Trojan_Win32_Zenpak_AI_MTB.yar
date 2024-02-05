
rule Trojan_Win32_Zenpak_AI_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 84 24 94 00 00 00 b9 6d 78 29 cc 89 44 24 24 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 24 29 c1 89 c8 83 e8 05 89 4c 24 20 89 44 24 1c 74 } //00 00 
	condition:
		any of ($a_*)
 
}