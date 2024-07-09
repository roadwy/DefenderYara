
rule Trojan_Win32_Glupteba_RF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 86 72 18 5f 46 89 ff e8 ?? ?? ?? ?? 01 f7 47 31 02 81 ee 01 00 00 00 81 c2 01 00 00 00 81 ef 9a f8 1a ff 4e 39 da 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 89 44 24 ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8d 14 37 31 54 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}