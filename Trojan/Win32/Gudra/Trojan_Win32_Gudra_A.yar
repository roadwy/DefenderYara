
rule Trojan_Win32_Gudra_A{
	meta:
		description = "Trojan:Win32/Gudra.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 3d 21 67 75 64 72 90 01 1b 53 20 6d 6f 64 65 2e 90 00 } //01 00 
		$a_01_1 = {6b 7a 2e 62 61 69 64 75 64 64 6e 2e 63 6f 6d 3a 33 33 39 30 30 } //01 00  kz.baiduddn.com:33900
		$a_01_2 = {6b 7a 2e 77 65 69 62 6f 63 64 6e 2e 6e 65 74 3a 33 33 39 30 30 } //01 00  kz.weibocdn.net:33900
		$a_01_3 = {36 31 2e 31 33 39 2e 32 2e 36 39 3a 35 33 } //01 00  61.139.2.69:53
		$a_00_4 = {47 00 75 00 64 00 72 00 41 00 6c 00 69 00 76 00 65 00 } //01 00  GudrAlive
		$a_00_5 = {47 00 75 00 64 00 72 00 46 00 69 00 6c 00 65 00 } //00 00  GudrFile
		$a_00_6 = {7e 15 00 } //00 f5 
	condition:
		any of ($a_*)
 
}