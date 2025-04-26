
rule Trojan_Win32_Qbot_AC_MTB{
	meta:
		description = "Trojan:Win32/Qbot.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d1 c7 45 e8 ?? ?? ?? ?? c7 45 ec ?? ?? ?? ?? 8a 44 15 ?? 34 ?? 88 44 15 ?? 42 83 fa 0c 7c ?? 88 4d ?? 8d 55 ?? eb } //1
		$a_03_1 = {8b d1 c7 45 f8 ?? ?? ?? ?? c6 45 fc ?? 8a 44 15 ?? 2c 2d 88 44 15 ?? 42 83 fa 09 7c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}