
rule Trojan_Win32_UrSnif_RPH_MTB{
	meta:
		description = "Trojan:Win32/UrSnif.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 c1 31 37 47 81 e8 01 00 00 00 48 39 d7 75 e6 81 e9 01 00 00 00 90 02 20 c3 8d 34 1e 01 c0 8b 36 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_UrSnif_RPH_MTB_2{
	meta:
		description = "Trojan:Win32/UrSnif.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 fc 0f be 02 89 45 f8 8b 4d 08 03 4d fc 51 } //01 00 
		$a_03_1 = {55 8b ec 53 8b 45 08 0f be 18 e8 90 01 04 33 d8 8b 4d 08 88 19 5b 5d c2 04 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}