
rule Trojan_Win32_Gandcrab_RL_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.RL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b cf 8b c7 c1 e9 ?? 03 4c 24 ?? c1 e0 ?? 03 44 24 ?? 33 c8 8d 04 2f 33 c8 2b d9 8b cb 8b c3 c1 e9 ?? 03 4c 24 ?? c1 e0 ?? 03 44 24 ?? 33 c8 8d 04 2b 2b 6c 24 ?? 33 c8 2b f9 83 ee ?? 75 } //1
		$a_02_1 = {69 c9 fd 43 03 00 6a 00 81 c1 c3 9e 26 00 6a 00 89 0d ?? ?? ?? ?? ff d3 8a 15 ?? ?? ?? ?? 30 14 3e 46 3b 75 0c 7c } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}