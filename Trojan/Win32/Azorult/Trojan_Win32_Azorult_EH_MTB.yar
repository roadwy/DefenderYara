
rule Trojan_Win32_Azorult_EH_MTB{
	meta:
		description = "Trojan:Win32/Azorult.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 02 00 00 00 8b 45 0c 90 01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}
rule Trojan_Win32_Azorult_EH_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f0 8b d6 c1 e2 04 89 44 24 14 89 54 24 10 8b 44 24 2c 01 44 24 10 8b c6 c1 e8 05 03 c5 03 fe } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Azorult_EH_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 c7 45 fc 02 00 00 00 8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d 0c 31 08 c9 c2 08 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Azorult_EH_MTB_4{
	meta:
		description = "Trojan:Win32/Azorult.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f0 8b ce c1 e1 04 89 44 24 14 89 4c 24 10 8b 44 24 28 01 44 24 10 8b d6 c1 ea 05 03 d5 8d 04 37 31 44 24 10 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Azorult_EH_MTB_5{
	meta:
		description = "Trojan:Win32/Azorult.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d c2 08 00 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 10 90 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule Trojan_Win32_Azorult_EH_MTB_6{
	meta:
		description = "Trojan:Win32/Azorult.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 c7 45 fc 02 00 00 00 8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d 0c 31 08 c9 c2 08 00 55 8b ec 8b 45 08 8b 4d 0c 01 08 5d c2 08 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}