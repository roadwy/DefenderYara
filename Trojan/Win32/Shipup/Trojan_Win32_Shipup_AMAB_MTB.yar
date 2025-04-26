
rule Trojan_Win32_Shipup_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Shipup.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 dc 89 f3 89 ca e8 ?? ?? ?? ?? 89 45 e8 89 f3 89 ca 8b 45 dc e8 ?? ?? ?? ?? 8b 55 e4 23 45 f4 01 c2 8b 45 e8 33 45 dc 8b 5d dc 03 45 e4 ff 45 fc e8 ?? ?? ?? ?? 81 7d fc e8 07 00 00 7d } //1
		$a_01_1 = {0f b6 00 8d 7b 01 99 f7 ff 88 45 fc 8a 06 0c 01 0f b6 f8 89 d8 99 f7 ff 0f b6 3e 01 f8 88 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Shipup_AMAB_MTB_2{
	meta:
		description = "Trojan:Win32/Shipup.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 e8 01 c2 8b 45 f0 03 45 e0 89 45 ec 8b 45 e8 03 45 ec 41 e8 ?? ?? ?? ?? 81 f9 e8 07 00 00 7d ?? 8b 45 e0 89 f3 89 fa e8 ?? ?? ?? ?? 89 45 f0 89 f3 89 fa 8b 45 e0 e8 ?? ?? ?? ?? 8b 5d e0 85 db 74 } //1
		$a_01_1 = {89 c6 89 d7 88 d9 0f b6 00 d3 f8 89 c1 0f b6 02 8d 53 01 89 55 fc 99 f7 7d fc 88 06 88 c8 0c 01 0f b6 f0 89 d8 99 f7 fe 0f b6 c9 01 c8 88 07 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}