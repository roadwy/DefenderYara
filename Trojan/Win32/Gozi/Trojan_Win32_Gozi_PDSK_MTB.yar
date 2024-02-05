
rule Trojan_Win32_Gozi_PDSK_MTB{
	meta:
		description = "Trojan:Win32/Gozi.PDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 4d fc 8b c6 5f 33 cd 25 ff 7f 00 00 5e e8 } //01 00 
		$a_00_1 = {8b 8d f8 f3 ff ff 30 04 31 46 3b f7 7c } //02 00 
		$a_02_2 = {8b 54 24 10 81 c7 98 69 cc 01 89 3a 0f b7 05 90 01 04 0f b7 15 90 01 04 03 c2 83 f8 17 89 44 24 14 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}