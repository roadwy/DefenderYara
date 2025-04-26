
rule Trojan_Win32_CiaDoor_GIS_MTB{
	meta:
		description = "Trojan:Win32/CiaDoor.GIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 8b 51 14 2b c2 8b 51 10 3b c2 89 85 bc fc ff ff 72 20 } //10
		$a_01_1 = {8b 41 14 8b 51 10 f7 d8 3b c2 89 85 bc fc ff ff 72 20 } //10
		$a_80_2 = {64 65 6c 20 61 2e 62 61 74 } //del a.bat  1
		$a_80_3 = {5c 74 65 6d 70 5c 6d 65 6c 74 2e 62 61 74 } //\temp\melt.bat  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=22
 
}