
rule Trojan_Win32_Amadey_AY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 50 8b 84 31 90 01 04 03 45 f4 50 ff 75 e4 ff 15 90 01 04 8b 4d f8 83 c3 28 0f b7 47 06 41 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Amadey_AY_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 43 ca 03 c1 3b f0 74 90 01 01 8a 0c 33 32 0e 8b 57 10 8b 5f 14 88 4d fc 3b d3 73 90 01 01 8d 42 01 89 47 10 8b c7 83 fb 10 72 90 01 01 8b 07 8b 5d ec 46 88 0c 10 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}