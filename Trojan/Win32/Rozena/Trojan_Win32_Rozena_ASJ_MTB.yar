
rule Trojan_Win32_Rozena_ASJ_MTB{
	meta:
		description = "Trojan:Win32/Rozena.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 5c 24 18 31 ed eb ?? 0f b6 34 ?? 31 ?? 83 f6 ?? 87 de 88 1c 28 87 de 45 } //2
		$a_03_1 = {8b 5c 24 1c 31 ed eb ?? 0f b6 34 ?? 31 ?? 83 f6 ?? 87 de 88 1c 28 87 de 45 } //2
		$a_03_2 = {83 ec 18 8b 05 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 89 04 24 89 4c 24 04 89 54 24 08 e8 ?? ?? ?? 00 8b 44 24 0c 8b 4c 24 10 8b 54 24 14 89 0d ?? ?? ?? 00 89 15 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 85 c9 75 } //3
		$a_01_3 = {6d 61 69 6e 2e 44 65 63 72 79 70 74 58 6f 72 } //1 main.DecryptXor
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*3+(#a_01_3  & 1)*1) >=6
 
}