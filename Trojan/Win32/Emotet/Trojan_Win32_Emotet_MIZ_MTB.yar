
rule Trojan_Win32_Emotet_MIZ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 8b 4d ec 8a 14 01 8b 75 f4 81 f6 c3 a7 ec 38 8b 7d e8 88 14 07 01 f0 8b 75 f0 39 f0 89 45 e4 74 d2 } //5
		$a_03_1 = {80 f3 27 8b 3d ?? ?? ?? ?? 81 c6 d0 aa 00 e4 89 4d b8 8b 4d c4 39 f1 8b 75 b8 0f 47 f2 2a 1c 37 8b 55 e4 8b 75 c0 02 1c 32 8b 7d bc 2b 7d ec 01 f1 8b 55 e0 88 1c 32 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}