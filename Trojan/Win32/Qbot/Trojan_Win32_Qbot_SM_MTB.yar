
rule Trojan_Win32_Qbot_SM_MTB{
	meta:
		description = "Trojan:Win32/Qbot.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 f0 8b 45 08 03 30 8b 4d 08 89 31 } //1
		$a_01_1 = {03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d c3 } //1
		$a_03_2 = {33 d9 c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5b 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}