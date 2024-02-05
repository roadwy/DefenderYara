
rule Trojan_Win32_TrickBotCrypt_EW_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b ca 8b 15 90 01 04 0f af 15 90 01 04 0f af 15 90 01 04 2b ca 03 0d 90 01 04 8b 55 0c 8b 75 08 8a 04 02 32 04 0e 8b 4d ec 2b 0d 90 01 04 03 0d 90 01 04 2b 0d 90 01 04 8b 55 0c 88 04 0a 90 00 } //01 00 
		$a_01_1 = {4c 3c 6b 29 67 65 25 56 5a 34 5a 53 6d 48 36 52 34 46 5e 2b 66 66 30 5e 51 30 34 58 69 57 4b 36 79 30 76 4c 67 28 6f 35 4b 62 72 36 5a 4e 30 4e 6b 5f 4b 3c 67 29 56 2b 5e 59 41 3c 4a 54 72 79 2a 6d 21 40 4d 6d 42 49 53 55 3e 7a 21 21 31 21 76 35 74 40 26 35 29 53 35 4a 44 66 50 23 30 68 21 32 43 65 6f 66 57 43 6e 6c 75 44 3e 40 51 50 } //00 00 
	condition:
		any of ($a_*)
 
}