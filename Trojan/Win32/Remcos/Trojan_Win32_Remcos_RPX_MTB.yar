
rule Trojan_Win32_Remcos_RPX_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 8b 4d f8 8d 14 30 8b 45 fc d3 ee 8b 4d d0 03 c1 33 c2 03 75 d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Remcos_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8d 1c ff ff ff 83 c1 01 89 8d 1c ff ff ff 8b 95 1c ff ff ff 3b 55 0c 73 2d 8b 85 1c ff ff ff 33 d2 f7 75 14 8b 45 10 0f b6 0c 10 8b 55 08 03 95 1c ff ff ff 0f b6 02 2b c1 8b 4d 08 03 8d 1c ff ff ff 88 01 eb b9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Remcos_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/Remcos.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5b 0f b6 8d 52 fc ff ff 8b 95 68 f8 ff ff 0f be 02 2b c1 8b 8d 68 f8 ff ff 88 01 eb 95 8b 95 4c f5 ff ff 89 95 20 e6 ff ff 8d 85 18 f3 ff ff 50 8b 8d 18 f3 ff ff 51 8b 95 6c e9 ff ff 52 8b 85 18 fc ff ff 50 ff 95 20 e6 ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}