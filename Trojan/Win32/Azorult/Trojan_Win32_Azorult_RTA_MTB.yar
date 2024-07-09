
rule Trojan_Win32_Azorult_RTA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 fe 93 8d 6a 8b 85 ?? ?? ?? ?? 8d 0c 17 33 c1 31 45 ?? 81 3d ?? ?? ?? ?? a3 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTA_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 03 44 24 ?? 83 3d ?? ?? ?? ?? 1b 89 44 24 ?? c7 05 ?? ?? ?? ?? fc 03 cf ff 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RTA_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 [0-04] 31 [0-04] 8b [0-0a] 03 [0-04] 33 [0-05] 83 [0-05] 27 c7 [0-05] 2e ce 50 91 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}