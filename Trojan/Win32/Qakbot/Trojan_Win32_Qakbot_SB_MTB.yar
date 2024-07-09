
rule Trojan_Win32_Qakbot_SB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 86 4c 01 00 00 31 46 ?? 48 89 86 ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 2d ?? ?? ?? ?? 89 46 ?? ff 77 ?? 8b 46 ?? 03 47 ?? 50 8b 47 ?? 03 46 ?? 50 e8 } //1
		$a_00_1 = {44 51 46 69 46 61 30 79 } //1 DQFiFa0y
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}