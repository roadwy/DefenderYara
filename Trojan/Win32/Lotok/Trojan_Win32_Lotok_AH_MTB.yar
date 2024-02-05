
rule Trojan_Win32_Lotok_AH_MTB{
	meta:
		description = "Trojan:Win32/Lotok.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8a 10 8a 4d ef 32 d1 02 d1 88 10 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}