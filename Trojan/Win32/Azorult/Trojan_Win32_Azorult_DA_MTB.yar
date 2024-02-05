
rule Trojan_Win32_Azorult_DA_MTB{
	meta:
		description = "Trojan:Win32/Azorult.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 1c 38 d3 ef c7 05 90 01 04 2e ce 50 91 89 7d f8 8b 45 90 01 01 01 45 f8 81 3d 90 01 04 eb 03 00 00 75 90 09 10 00 c7 05 90 01 04 40 2e eb ed 8b 45 90 01 01 8b 4d 90 00 } //01 00 
		$a_02_1 = {d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 90 09 1a 00 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 04 ff ff ff ff 8b 45 f4 8b 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Azorult_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.DA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {c7 45 f4 02 00 00 00 83 45 f4 03 8b 8d 1c fd ff ff 8b c3 c1 e0 04 89 85 30 fd ff ff 8d 85 30 fd ff ff } //05 00 
		$a_01_1 = {8b 4d f8 03 cb 8b 85 2c fd ff ff c1 e8 05 89 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}