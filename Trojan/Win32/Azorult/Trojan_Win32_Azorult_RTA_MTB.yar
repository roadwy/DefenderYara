
rule Trojan_Win32_Azorult_RTA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8b 85 90 01 04 8d 0c 17 33 c1 31 45 90 01 01 81 3d 90 01 04 a3 01 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTA_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 44 24 90 01 01 83 3d 90 01 04 1b 89 44 24 90 01 01 c7 05 90 01 04 fc 03 cf ff 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTA_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 90 02 04 31 90 02 04 8b 90 02 0a 03 90 02 04 33 90 02 05 83 90 02 05 27 c7 90 02 05 2e ce 50 91 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}