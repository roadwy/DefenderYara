
rule Trojan_BAT_Tiny_A_MTB{
	meta:
		description = "Trojan:BAT/Tiny.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 0f 00 06 00 00 "
		
	strings :
		$a_02_0 = {0a 2d 1c 7e 07 90 01 02 04 7e 90 01 03 04 28 90 01 03 0a 7e 90 01 03 04 28 90 01 03 0a 26 2b 27 7e 90 01 03 04 18 2f 0e 7e 90 01 03 04 17 d6 80 90 01 03 04 2b 11 16 80 90 01 03 04 7e 90 01 03 04 28 90 01 03 0a 26 2b 2c 16 90 00 } //10
		$a_80_1 = {53 65 6c 65 63 74 20 43 6f 6d 6d 61 6e 64 4c 69 6e 65 20 66 72 6f 6d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 20 77 68 65 72 65 20 4e 61 6d 65 3d 27 7b 30 7d 27 } //Select CommandLine from Win32_Process where Name='{0}'  5
		$a_80_2 = {41 45 53 5f 44 65 63 72 79 70 74 6f 72 } //AES_Decryptor  4
		$a_80_3 = {57 44 4c 6f 6f 70 } //WDLoop  3
		$a_80_4 = {43 68 65 63 6b 50 72 6f 63 } //CheckProc  3
		$a_80_5 = {57 61 74 63 68 64 6f 67 } //Watchdog  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*4+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=15
 
}