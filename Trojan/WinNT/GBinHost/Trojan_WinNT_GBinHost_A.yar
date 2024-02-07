
rule Trojan_WinNT_GBinHost_A{
	meta:
		description = "Trojan:WinNT/GBinHost.A,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 73 00 5c 00 47 00 62 00 50 00 6c 00 75 00 67 00 69 00 6e 00 } //02 00  Programas\GbPlugin
		$a_00_1 = {00 00 70 00 64 00 69 00 73 00 74 00 00 00 63 00 65 00 66 00 00 00 } //02 00 
		$a_00_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 } //0a 00  Windows\system32\drivers
		$a_01_3 = {8b 45 0c 48 c6 03 01 89 7b 04 74 3d 48 74 32 48 74 27 } //00 00 
		$a_00_4 = {80 10 00 00 7c 9e a7 9c f5 3b 5d 9d e8 fa } //ff f4 
	condition:
		any of ($a_*)
 
}