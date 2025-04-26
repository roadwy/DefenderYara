
rule Trojan_Win32_Qbot_BA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {3d 65 87 00 00 74 ?? e8 ?? ?? ?? ?? 89 c8 58 8b 3d ?? ?? ?? ?? 40 05 ?? ?? ?? ?? 89 e8 57 83 c0 06 83 e8 01 48 5e 89 47 04 40 05 ?? ?? ?? ?? 58 89 47 0c ba 14 00 00 00 81 2c 32 ?? ?? ?? ?? 8b 14 32 52 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Qbot_BA_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d c3 } //1
		$a_03_1 = {03 4d fc 8b 15 ?? ?? ?? 00 03 55 fc 8a 02 88 01 8b 4d fc 83 c1 01 89 4d fc eb } //1
		$a_03_2 = {58 8b e8 8b 15 ?? ?? ?? 00 52 8b 15 ?? ?? ?? 00 52 8b 15 ?? ?? ?? 00 52 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}