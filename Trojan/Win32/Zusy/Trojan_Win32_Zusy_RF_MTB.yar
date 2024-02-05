
rule Trojan_Win32_Zusy_RF_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 04 52 83 7c 90 01 01 14 08 8d 04 90 01 01 72 02 8b 00 8d 4c 24 90 01 01 51 8d 4c 24 90 01 01 51 6a 00 6a 00 68 04 00 00 08 6a 00 6a 00 6a 00 6a 00 50 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e1 06 8b 55 90 01 01 c1 ea 08 33 ca 03 4d 90 01 01 8b 45 90 01 01 33 d2 f7 75 ec 8b 45 90 01 01 03 0c 90 01 01 03 4d 90 01 01 8b 55 f0 2b d1 89 55 f0 8b 45 f0 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}