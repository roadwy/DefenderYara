
rule Trojan_Win32_Qbot_FC_MTB{
	meta:
		description = "Trojan:Win32/Qbot.FC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 57 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 89 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 8b 02 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 81 e9 ?? ?? ?? 00 89 0d ?? ?? ?? 00 8b 0d ?? ?? ?? 00 81 c1 ?? ?? ?? 00 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 31 0d ?? ?? ?? 00 c7 05 ?? ?? ?? 00 00 00 00 00 a1 ?? ?? ?? 00 01 05 ?? ?? ?? 00 [0-05] 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 89 02 5f 5d c3 } //1
		$a_03_1 = {03 f0 8b 4d ?? 03 31 8b 55 ?? 89 32 5e 8b e5 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}