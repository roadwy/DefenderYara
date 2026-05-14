
rule Trojan_Win64_Injector_SXE_MTB{
	meta:
		description = "Trojan:Win64/Injector.SXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_03_0 = {49 8b d4 49 8b cf ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 48 39 7d e8 0f 85 ?? ?? ?? ?? 4c 89 6c 24 30 44 89 6c 24 28 4c 89 64 24 20 4c 8b 0d ?? ?? ?? ?? 45 33 c0 33 d2 49 8b cf ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 } //30
		$a_01_1 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 69 6e 6a 65 63 74 65 64 } //10 Successfully injected
		$a_01_2 = {62 79 70 61 73 73 20 61 6e 74 69 2d 63 68 65 61 74 20 68 6f 6f 6b } //10 bypass anti-cheat hook
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=50
 
}