
rule Trojan_Win32_Qbot_PA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 89 e5 57 56 83 e4 ?? 83 ec ?? 8a 45 ?? 8b 4d ?? 8b 55 ?? 8b 75 ?? c6 44 24 ?? ?? 83 fe 00 88 44 24 ?? 89 4c 24 ?? 89 54 24 ?? 89 74 24 ?? 74 ?? 8b 44 24 ?? 05 ?? ?? ?? ?? 8a 4c 24 ?? 89 44 24 ?? 80 c1 ?? 8a 54 24 ?? 28 d1 8b 44 24 ?? 8b 74 24 ?? 8a 2c 30 00 e9 8b 7c 24 ?? 88 0c 37 8a 4c 24 ?? 88 4c 24 ?? 8d 65 ?? 5e 5f 5d c3 } //1
		$a_00_1 = {0f 31 89 d6 89 c7 0f 31 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}