
rule Trojan_Win32_Qbot_FE_MTB{
	meta:
		description = "Trojan:Win32/Qbot.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 89 10 b9 6e 00 00 00 8b 15 ?? ?? ?? ?? 66 89 4a 02 b8 74 00 00 00 90 0a 20 00 ba 69 00 00 00 a1 ?? ?? ?? ?? 66 89 10 b9 6e 00 00 00 } //1
		$a_01_1 = {03 f0 8b 4d 08 8b 11 2b d6 8b 45 08 89 10 5e 8b e5 5d c3 } //1
		$a_03_2 = {8b d8 33 d9 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}