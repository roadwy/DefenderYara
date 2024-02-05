
rule Backdoor_Win32_Delf_RAN{
	meta:
		description = "Backdoor:Win32/Delf.RAN,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6b 72 6e 6c 73 72 76 63 } //01 00 
		$a_00_1 = {45 52 41 53 45 20 2f 46 20 2f 41 20 22 } //01 00 
		$a_00_2 = {22 20 67 6f 74 6f 20 54 4e 4e 44 } //0a 00 
		$a_02_3 = {8d 45 fc ba 04 00 00 00 e8 90 01 04 8b 55 fc 8d 85 2c fd ff ff e8 90 01 04 8d 85 2c fd ff ff e8 90 01 04 e8 90 01 04 ba 90 01 04 8d 85 2c fd ff ff e8 90 01 04 e8 90 01 04 e8 90 01 04 68 90 01 04 8d 85 1c fd ff ff 8d 95 f8 fe ff ff b9 04 01 00 00 e8 90 01 04 ff b5 1c fd ff ff 68 90 01 04 8d 85 20 fd ff ff ba 03 00 00 00 90 00 } //0a 00 
		$a_02_4 = {84 c0 74 59 8b 45 f4 e8 90 01 04 83 fa 00 75 07 83 f8 00 72 39 eb 02 7c 35 ff 36 68 90 01 04 8b 45 f4 e8 90 01 04 52 50 8d 85 90 01 04 e8 90 01 04 ff b5 90 01 04 68 90 01 04 8b c6 ba 04 00 00 00 e8 90 01 04 eb 1a 8b c6 ba 90 01 04 e8 90 01 04 eb 0c 8b c6 ba 90 01 04 e8 90 01 04 33 c0 5a 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}