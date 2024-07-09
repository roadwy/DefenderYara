
rule Trojan_Win32_Qbot_KPV_MTB{
	meta:
		description = "Trojan:Win32/Qbot.KPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 4d 08 8b 11 81 ea c2 5a 00 00 8b 45 08 89 10 8b e5 5d c3 } //2
		$a_02_1 = {8b c7 c1 e9 05 03 0d ?? ?? ?? ?? c1 e0 04 03 05 ?? ?? ?? ?? 33 c8 8d 04 3b 33 c8 8d 9b ?? ?? ?? ?? 2b f1 83 ea 01 75 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}