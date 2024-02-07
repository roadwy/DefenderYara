
rule TrojanSpy_Win32_Bancos_AGH{
	meta:
		description = "TrojanSpy:Win32/Bancos.AGH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 37 85 db 74 15 8a 02 3c 61 72 06 3c 7a 77 02 2c 20 88 06 42 46 4b } //01 00 
		$a_03_1 = {66 74 70 54 72 61 6e 73 66 65 72 90 02 02 66 74 70 52 65 61 64 79 90 00 } //01 00 
		$a_01_2 = {20 63 61 6d 70 6f 20 73 6f 6c 69 63 69 74 61 64 6f 00 } //01 00  挠浡潰猠汯捩瑩摡o
		$a_01_3 = {2f 74 65 6d 70 45 50 2f 64 6c 66 2f 66 62 2e 70 68 70 00 } //01 00 
		$a_01_4 = {63 72 6f 73 73 40 68 6f 74 6d 61 69 6c 2e 63 6f 6d 00 } //00 00 
	condition:
		any of ($a_*)
 
}