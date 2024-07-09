
rule TrojanDropper_Win32_Pirpi_B{
	meta:
		description = "TrojanDropper:Win32/Pirpi.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 3b 4d 10 7d 2a 8b 55 fc 8a 44 15 ?? 32 45 08 8b 4d fc 88 44 0d 90 1b 00 8b 55 0c 03 55 fc 8b 45 fc 8a 0a 32 4c 05 90 1b 00 8b 55 0c 03 55 fc 88 0a eb } //1
		$a_03_1 = {83 7d f4 00 74 14 81 7d f4 ?? ?? ?? ?? 74 0b 8b 45 f4 35 90 1b 00 89 45 f4 6a 00 8d 8d ?? ?? ff ff 51 6a 04 8d 55 f4 52 8b 85 ?? ?? ff ff 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}