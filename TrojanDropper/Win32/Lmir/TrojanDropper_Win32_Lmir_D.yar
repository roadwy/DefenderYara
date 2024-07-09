
rule TrojanDropper_Win32_Lmir_D{
	meta:
		description = "TrojanDropper:Win32/Lmir.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 c4 f0 c7 45 ?? 25 73 6d 6d c7 45 ?? 78 25 6c 78 c7 45 ?? 2e 65 78 65 c6 45 fc 00 e8 } //1
		$a_00_1 = {48 78 0d 80 3c 30 5c 75 f7 66 c7 44 30 01 77 74 } //1
		$a_03_2 = {50 68 09 4a 00 00 51 [0-08] e8 } //1
		$a_03_3 = {6a 01 53 e8 ?? ?? ?? ?? ff d0 6a 04 53 e8 ?? ?? ?? ?? 8b f0 6a 01 ff d6 0b c0 74 1f 50 6a 00 68 ff 0f 1f 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=2
 
}