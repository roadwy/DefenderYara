
rule Trojan_Win32_Zbot_MMW_MTB{
	meta:
		description = "Trojan:Win32/Zbot.MMW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {55 31 35 b5 50 40 00 8b 14 24 01 f2 8b 0c 24 13 0d ?? ?? ?? ?? 8b 04 24 01 f0 8b 14 24 01 c2 29 35 ?? ?? ?? ?? 29 f6 } //10
		$a_80_1 = {73 7a 67 66 77 2e 65 78 65 } //szgfw.exe  1
		$a_01_2 = {68 77 69 77 6a 67 74 71 6b 79 72 6a 6c 65 71 6c 64 } //1 hwiwjgtqkyrjleqld
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}