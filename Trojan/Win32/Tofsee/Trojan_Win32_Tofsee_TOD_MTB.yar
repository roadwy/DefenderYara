
rule Trojan_Win32_Tofsee_TOD_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.TOD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f5 03 dd c1 ee 05 89 44 24 14 83 f9 1b 75 90 01 01 ff 15 90 01 04 8b 44 24 14 03 74 24 20 c7 05 90 01 04 00 00 00 00 33 f3 33 f0 2b fe 8b d7 c1 e2 04 89 54 24 14 8b 44 24 28 01 44 24 14 8b 5c 24 18 8b 0d 04 c8 2d 02 03 df 81 f9 be 01 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}