
rule Trojan_Win32_Fuery_ASN_MTB{
	meta:
		description = "Trojan:Win32/Fuery.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 7c 24 28 04 01 00 00 73 19 8a 08 8a d9 80 f3 98 88 1c 02 8b 5c 24 1c 88 4c 3e 0c 40 47 80 38 00 75 } //01 00 
		$a_01_1 = {8b 55 08 31 56 04 8b 45 08 31 46 08 8b 7d 0c 8b cf 6b c9 4c 03 4d 10 } //01 00 
		$a_01_2 = {0f b6 10 66 52 8b 1e 81 c3 08 d2 cd 7e 03 1f 81 c6 04 00 00 00 55 89 1c 24 e8 } //01 00 
		$a_01_3 = {68 1b 64 21 01 51 e8 } //00 00 
	condition:
		any of ($a_*)
 
}