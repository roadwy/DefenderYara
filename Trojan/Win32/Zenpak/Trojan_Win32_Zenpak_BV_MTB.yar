
rule Trojan_Win32_Zenpak_BV_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 45 0c 8a 4d 08 8b 15 90 01 04 30 c8 a2 90 01 04 81 c2 8d cf ff ff 89 15 90 01 04 c7 05 90 01 04 4a 1b 00 00 0f b6 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}