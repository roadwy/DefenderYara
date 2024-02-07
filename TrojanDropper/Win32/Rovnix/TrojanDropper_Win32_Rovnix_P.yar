
rule TrojanDropper_Win32_Rovnix_P{
	meta:
		description = "TrojanDropper:Win32/Rovnix.P,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 19 0f be 55 10 8b 45 08 03 45 fc 0f be 08 33 ca 8b 55 08 03 55 fc 88 0a eb d6 } //01 00 
		$a_01_1 = {b8 68 58 4d 56 } //01 00 
		$a_01_2 = {42 6b 49 6e 73 74 61 6c 6c 00 } //01 00  歂湉瑳污l
		$a_01_3 = {6a 04 8d 4d d4 51 68 18 00 36 83 8b 55 dc 52 ff 15 } //01 00 
		$a_01_4 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 55 00 41 00 43 00 25 00 73 00 25 00 75 00 } //01 00  Global\UAC%s%u
		$a_01_5 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 42 00 44 00 25 00 73 00 25 00 75 00 } //00 00  Global\BD%s%u
	condition:
		any of ($a_*)
 
}