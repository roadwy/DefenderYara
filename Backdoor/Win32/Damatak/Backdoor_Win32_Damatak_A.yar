
rule Backdoor_Win32_Damatak_A{
	meta:
		description = "Backdoor:Win32/Damatak.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 69 6e 68 6f 73 74 33 32 2e 65 78 65 } //01 00  winhost32.exe
		$a_00_1 = {7a 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //01 00  zexplorer.exe
		$a_00_2 = {67 75 69 64 3d 25 69 36 34 75 26 62 75 69 6c 64 3d 25 73 26 69 6e 66 6f 3d 25 73 26 69 70 3d 25 73 26 74 79 70 65 3d 31 26 77 69 6e 3d 25 64 2e 25 64 28 78 } //01 00  guid=%i64u&build=%s&info=%s&ip=%s&type=1&win=%d.%d(x
		$a_00_3 = {2e 63 66 67 00 00 00 00 2e 65 78 65 00 } //01 00 
		$a_00_4 = {68 74 74 70 3a 2f 2f 61 70 69 2e 69 70 69 66 79 2e 6f 72 67 00 00 00 00 30 2e 30 2e 30 2e 30 } //01 00 
		$a_03_5 = {75 12 83 7d f8 00 75 0c 8b 4d f0 51 e8 90 01 04 83 c4 04 83 7d e8 00 75 02 eb 02 eb 90 00 } //01 00 
		$a_01_6 = {8b 4f 10 33 c0 85 c9 74 09 80 34 30 a1 40 3b c1 72 f7 } //00 00 
		$a_00_7 = {87 10 00 } //00 38 
	condition:
		any of ($a_*)
 
}