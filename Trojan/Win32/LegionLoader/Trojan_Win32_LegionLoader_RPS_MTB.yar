
rule Trojan_Win32_LegionLoader_RPS_MTB{
	meta:
		description = "Trojan:Win32/LegionLoader.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 55 b8 8b 45 b0 2d ?? ?? ?? ?? 89 45 b0 8b 4d c4 81 e9 ?? ?? ?? ?? 89 4d c4 8b 55 cc 03 55 c0 89 55 cc 8b 45 c4 2b 45 ac 89 45 c4 8b 4d c0 81 c1 ?? ?? ?? ?? 89 4d c0 8b 95 ?? ?? ?? ?? 8b 45 94 89 02 } //1
		$a_01_1 = {74 0b 8b 55 d8 83 c2 01 89 55 d8 eb e6 8b 45 a8 2b 45 d8 89 45 a8 8b 4d b8 81 e9 f3 1c 00 00 89 4d b8 8b 95 2c ff ff ff 8b 85 74 ff ff ff 89 02 90 90 90 90 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}