
rule Trojan_Win32_Zbot_SIBG3_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBG3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 04 00 00 "
		
	strings :
		$a_80_0 = {62 75 64 68 61 2e 65 78 65 } //budha.exe  1
		$a_02_1 = {6b 00 69 00 6c 00 66 00 [0-05] 2e 00 65 00 78 00 65 00 } //1
		$a_02_2 = {6b 69 6c 66 [0-05] 2e 65 78 65 } //1
		$a_02_3 = {2b ce 3b c8 74 ?? ff 45 ?? 83 7d 90 1b 01 ?? 7c ?? 83 7d 90 1b 01 ?? 0f 84 ?? ?? ?? ?? 80 3e ?? 74 ?? 80 7e ?? ?? 74 ?? c1 e0 ?? 50 6a ?? ff 75 ?? ff 15 ?? ?? ?? ?? 89 45 ?? 3b c3 0f 84 ?? ?? ?? ?? 8b 7d ?? 8b 45 ?? 8b 40 ?? 8b d7 33 c9 83 e7 ?? c1 e2 ?? 41 89 5d ?? 83 ff ?? 76 ?? 31 04 8e 8b 7d 90 1b 12 41 c1 ef ?? 3b cf 72 } //10
	condition:
		((#a_80_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*10) >=10
 
}