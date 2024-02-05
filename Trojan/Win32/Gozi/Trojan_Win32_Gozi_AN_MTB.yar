
rule Trojan_Win32_Gozi_AN_MTB{
	meta:
		description = "Trojan:Win32/Gozi.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {8b 75 ac 89 16 8b 55 bc 8b 0a 8b 55 c0 8b 12 0f b6 0c 0a 8b 16 8b 75 c8 8b 36 0f b6 14 16 31 d1 8b 55 bc 8b 32 8b 55 b8 8b 12 88 0c 32 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_AN_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {0f b7 c0 6a 19 99 5b f7 fb 80 c2 61 88 14 31 41 3b cf 72 d7 } //02 00 
		$a_01_1 = {43 6f 53 65 74 50 72 6f 78 79 42 6c 61 6e 6b 65 74 } //02 00 
		$a_01_2 = {49 6e 74 65 72 6e 65 74 43 61 6e 6f 6e 69 63 61 6c 69 7a 65 55 72 6c 41 } //02 00 
		$a_01_3 = {47 65 74 53 69 64 53 75 62 41 75 74 68 6f 72 69 74 79 43 6f 75 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}