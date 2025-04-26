
rule Trojan_Win32_Glupteba_DA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c8 c1 e8 05 89 45 74 c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? fe ff ff 01 45 74 8b 55 74 33 d1 33 d3 8d 8d ?? fe ff ff 89 55 74 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 14 8b 54 24 10 8b c1 c1 e8 05 03 44 24 2c 03 d5 33 c2 03 cb 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 18 c7 05 ?? ?? ?? ?? 00 00 00 00 89 54 24 10 8b 44 24 24 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}