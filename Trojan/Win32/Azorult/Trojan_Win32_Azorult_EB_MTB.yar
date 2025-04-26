
rule Trojan_Win32_Azorult_EB_MTB{
	meta:
		description = "Trojan:Win32/Azorult.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 83 65 fc 00 8b 45 0c 89 45 fc 8b 45 08 31 45 fc 8b 45 fc 89 01 c9 c2 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Azorult_EB_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 c7 45 fc 04 00 00 00 8b 45 0c 83 6d fc 04 90 01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Azorult_EB_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d ec 8b c7 d3 e0 8b 4d f4 8b d7 d3 ea 03 45 d4 89 45 fc 8b 45 e8 03 55 d0 03 c7 89 45 f0 8b 45 f0 31 45 fc 31 55 fc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Azorult_EB_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d e4 8b d6 d3 e2 89 5d e8 03 55 c8 89 55 f4 8b 45 f0 01 45 e8 8b 45 dc 90 01 45 e8 8b 45 e8 89 45 e0 8b 4d ec 8b c6 d3 e8 89 45 f8 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}