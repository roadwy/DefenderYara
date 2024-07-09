
rule Trojan_Win32_RedLine_BD_MTB{
	meta:
		description = "Trojan:Win32/RedLine.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 ?? 03 45 ?? 03 fe 31 7d ?? 50 89 45 ?? 8d 45 ?? 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLine_BD_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 8a 88 [0-04] 88 4d f3 0f b6 4d f3 8b 45 f4 33 d2 f7 75 ec 0f b6 92 [0-04] 33 ca 88 4d fb 8b 45 f4 8a 88 [0-04] 88 4d f2 0f b6 55 fb 8b 45 f4 0f b6 88 [0-04] 03 ca 8b 55 f4 88 8a [0-04] 83 7d f4 64 76 } //4
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}