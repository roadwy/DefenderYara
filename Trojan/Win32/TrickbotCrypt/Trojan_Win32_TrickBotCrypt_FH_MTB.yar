
rule Trojan_Win32_TrickBotCrypt_FH_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 75 0c 8a 04 06 32 04 0a 8b 0d 90 01 04 0f af 0d 90 01 04 8b 15 90 01 04 0f af 15 90 01 04 8b 75 ec 2b 35 90 01 04 2b 35 90 01 04 2b f2 2b 35 90 01 04 03 f1 2b 35 90 01 04 03 35 90 01 04 8b 4d 0c 88 04 31 e9 90 00 } //01 00 
		$a_81_1 = {6e 68 64 21 51 59 62 39 4f 4d 61 4a 6c 32 36 21 5a 6f 52 39 5e 69 44 52 30 63 47 52 3c 3c 38 79 76 3c 35 54 50 24 69 78 6d 31 67 3c 41 73 6f 39 23 36 30 32 6f 38 4e 40 78 72 49 28 72 65 77 63 53 59 37 42 54 77 54 42 6f 24 23 74 68 2b 6a 5a } //00 00 
	condition:
		any of ($a_*)
 
}