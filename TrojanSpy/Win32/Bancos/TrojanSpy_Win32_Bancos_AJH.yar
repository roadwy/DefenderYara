
rule TrojanSpy_Win32_Bancos_AJH{
	meta:
		description = "TrojanSpy:Win32/Bancos.AJH,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0e 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {7e 35 be 01 00 00 00 8b 45 ec 0f b6 7c 30 ff 8b 45 e0 0f b6 00 89 45 f4 8d 45 e4 8b d7 2b 55 f4 2b 55 f0 e8 } //01 00 
		$a_11_1 = {6d 74 70 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 00 01 } //00 0c 
		$a_42_2 = {61 64 65 73 63 6f 20 50 72 69 01 00 10 11 2e 77 68 } //73 65 
		$a_76_3 = {64 6f 72 2e 63 6f 6d 00 01 00 09 11 4d 4f 56 54 4f 5f 49 53 5f 01 00 07 01 54 46 46 30 30 31 00 02 00 1b 01 42 61 6e 63 6f 20 49 74 61 fa 20 2d 20 46 65 69 74 6f 20 50 61 72 61 20 56 6f 63 00 00 5d 04 00 00 98 fb 02 80 5c 27 00 00 99 fb 02 80 00 00 01 00 1e 00 11 00 d1 61 43 56 45 2d 32 30 31 32 2d 33 32 31 33 2e 41 00 00 01 40 05 82 59 00 } //04 00 
	condition:
		any of ($a_*)
 
}