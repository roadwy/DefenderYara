
rule Trojan_Win32_Emotetcrypt_IO_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 14 1a 03 c2 99 bd 90 01 04 f7 fd 8b 44 24 58 8b 6c 24 1c 83 c5 01 89 6c 24 1c 03 54 24 4c 03 d7 03 54 24 50 0f b6 14 02 8b 44 24 18 30 54 28 ff 90 00 } //01 00 
		$a_81_1 = {23 24 49 44 79 3e 44 42 68 43 42 4a 54 40 32 36 24 42 5f 50 4f 21 21 4a 31 29 32 76 4d 35 4d 66 7a 28 33 31 79 50 4c 40 2a 4d 72 26 54 28 6d 73 56 41 73 39 59 42 5e 47 54 38 78 42 3c 42 61 2a 2b 64 79 4a 5f 40 28 51 2a 74 66 79 44 76 26 50 65 57 24 33 4e 26 6f 39 41 6a 2a 5e 29 44 68 44 5f 21 4a 48 6f 23 5e } //00 00 
	condition:
		any of ($a_*)
 
}