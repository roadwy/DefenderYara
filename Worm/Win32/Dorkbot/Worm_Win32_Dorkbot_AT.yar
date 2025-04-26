
rule Worm_Win32_Dorkbot_AT{
	meta:
		description = "Worm:Win32/Dorkbot.AT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b f8 2b f7 8a 1c 06 32 da 32 1d ?? ?? ?? ?? fe c2 88 18 40 3a d1 72 ec } //1
		$a_03_1 = {0f b6 c1 8a 14 10 32 15 ?? ?? ?? ?? 32 d1 fe c1 88 94 05 ?? ?? ff ff 3a 0d ?? ?? ?? ?? 72 db 90 09 06 00 8b 15 } //1
		$a_01_2 = {6a 00 6a 09 68 00 01 00 00 57 ff d6 6a 32 ff d3 6a 00 6a 09 68 01 01 00 00 57 ff d6 6a 32 ff d3 6a 00 6a 02 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*10) >=1
 
}