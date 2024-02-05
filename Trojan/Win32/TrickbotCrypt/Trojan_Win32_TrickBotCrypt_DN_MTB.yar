
rule Trojan_Win32_TrickBotCrypt_DN_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 09 00 00 06 00 "
		
	strings :
		$a_03_0 = {8b 55 08 33 db 8a 1c 0a 03 c3 33 d2 f7 35 90 01 04 89 55 f4 8b 45 fc 8b 08 8b 55 e4 8b 02 8b 55 08 33 db 8a 1c 02 90 00 } //0a 00 
		$a_01_1 = {2b da 8b 45 0c 8a 0c 08 32 cb 8b 55 fc 8b 02 8b 55 0c 88 0c 02 e9 } //0a 00 
		$a_81_2 = {48 74 74 70 41 6e 61 6c 79 7a 65 72 2e 45 58 45 } //01 00 
		$a_81_3 = {44 69 73 61 62 6c 65 54 68 72 65 61 64 4c 69 62 72 61 72 79 43 61 6c 6c 73 } //01 00 
		$a_81_4 = {53 74 61 72 74 57 } //01 00 
		$a_81_5 = {41 56 74 79 70 65 5f 69 6e 66 6f } //01 00 
		$a_81_6 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 41 } //01 00 
		$a_81_7 = {6b 61 6e 6a 69 6d 65 6e 75 } //01 00 
		$a_81_8 = {68 61 6e 67 65 75 6c 6d 65 6e 75 } //00 00 
	condition:
		any of ($a_*)
 
}