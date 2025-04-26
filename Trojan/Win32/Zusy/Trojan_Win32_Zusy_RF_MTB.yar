
rule Trojan_Win32_Zusy_RF_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 52 83 7c ?? 14 08 8d 04 ?? 72 02 8b 00 8d 4c 24 ?? 51 8d 4c 24 ?? 51 6a 00 6a 00 68 04 00 00 08 6a 00 6a 00 6a 00 6a 00 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zusy_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 06 8b 55 ?? c1 ea 08 33 ca 03 4d ?? 8b 45 ?? 33 d2 f7 75 ec 8b 45 ?? 03 0c ?? 03 4d ?? 8b 55 f0 2b d1 89 55 f0 8b 45 f0 89 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}