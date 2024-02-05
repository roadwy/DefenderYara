
rule Trojan_Win32_TrickBotCrypt_FC_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 7c 24 18 6a 00 6a 00 ff 15 90 01 04 8b c6 33 d2 b9 1f 90 01 03 f7 f1 8a 04 3e 8a 14 2a 32 c2 88 04 3e 90 00 } //01 00 
		$a_81_1 = {47 75 68 39 64 76 47 55 37 50 58 64 5a 32 41 58 4a 71 59 65 4d 71 63 4c 4b 66 70 53 48 55 30 54 73 79 37 37 6b 32 38 77 4e 54 4f 59 35 44 36 50 5a 61 44 49 49 33 4a 74 48 64 36 34 5a 6d 32 42 41 6b 59 57 71 65 75 32 6b 68 48 46 75 69 41 4e 67 65 6d 6e 6f 59 5a 51 50 51 6d 72 62 55 } //00 00 
	condition:
		any of ($a_*)
 
}