
rule Trojan_Win32_Telject_A{
	meta:
		description = "Trojan:Win32/Telject.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b c6 99 bb 0f 00 00 00 f7 fb 8a 01 8a 54 14 14 3a c2 74 90 01 01 32 c2 88 04 0f 46 41 3b f5 7c 90 01 01 8b 54 24 10 c6 04 32 00 90 00 } //05 00 
		$a_00_1 = {8b c6 99 bd 0f 00 00 00 f7 fd 8a 01 8a 54 14 14 3a c2 74 02 32 c2 88 04 0f 46 41 3b f3 7c e1 } //05 00 
		$a_03_2 = {8d 54 24 18 8b f0 e8 90 01 04 8d 44 24 18 50 53 53 ff d6 90 00 } //05 00 
		$a_00_3 = {85 c0 0f 84 80 00 00 00 8d 8c 24 60 01 00 00 8d 44 24 2c 8a 10 3a 11 75 1a 84 d2 } //02 00 
		$a_00_4 = {61 70 70 66 72 65 65 74 6f 6f 6c 73 2e 63 6f 6d 20 } //02 00  appfreetools.com 
		$a_00_5 = {63 6f 6c 6f 72 62 61 6c 6c 73 6f 75 74 2e 63 6f 6d } //03 00  colorballsout.com
		$a_00_6 = {53 75 70 70 6f 72 74 2f 6c 69 62 73 2f 61 64 73 6c 69 73 74 73 2e 70 68 70 } //05 00  Support/libs/adslists.php
		$a_01_7 = {50 49 6e 47 20 20 20 20 20 33 2e 33 2e 33 2e 32 35 35 20 2d 77 20 20 20 20 20 32 30 30 30 20 20 20 2d 6e 20 31 } //00 00  PInG     3.3.3.255 -w     2000   -n 1
	condition:
		any of ($a_*)
 
}