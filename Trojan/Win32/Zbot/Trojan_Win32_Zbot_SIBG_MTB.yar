
rule Trojan_Win32_Zbot_SIBG_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 03 00 00 "
		
	strings :
		$a_80_0 = {62 75 64 68 61 2e 65 78 65 } //budha.exe  1
		$a_80_1 = {6b 69 6c 66 2e 65 78 65 } //kilf.exe  1
		$a_02_2 = {8b 16 31 c2 8b 5d ?? 29 da 29 c3 c1 c8 ?? 89 45 ?? 89 5d 90 1b 00 89 16 83 c6 ?? e2 e5 } //10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*10) >=11
 
}