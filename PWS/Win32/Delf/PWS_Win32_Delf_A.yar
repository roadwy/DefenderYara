
rule PWS_Win32_Delf_A{
	meta:
		description = "PWS:Win32/Delf.A,SIGNATURE_TYPE_PEHSTR,33 00 33 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {3a 50 61 73 73 28 } //0a 00  :Pass(
		$a_01_1 = {4f 75 74 6c 6f 6f 6b 44 65 63 72 79 70 74 } //0a 00  OutlookDecrypt
		$a_01_2 = {73 79 73 74 65 6d 33 32 2e 65 78 65 20 45 4e 41 42 4c 45 } //0a 00  system32.exe ENABLE
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_4 = {31 32 37 2e 30 2e 30 2e 31 20 75 70 64 61 74 65 73 2e 73 79 6d 61 6e 74 65 63 2e 63 6f 6d } //01 00  127.0.0.1 updates.symantec.com
		$a_01_5 = {62 72 69 61 6e 32 31 30 } //01 00  brian210
		$a_01_6 = {6d 65 79 65 74 65 35 30 34 } //01 00  meyete504
		$a_01_7 = {38 34 2e 32 35 32 2e 31 34 38 2e 31 38 } //01 00  84.252.148.18
		$a_01_8 = {66 74 70 2e 6e 69 6b 61 76 6f 6e 65 6a 61 6c 6b 6f 2e 63 6f 2e 75 6b } //01 00  ftp.nikavonejalko.co.uk
		$a_01_9 = {7b 44 45 44 46 46 36 32 34 2d 33 43 43 42 2d 31 31 44 39 2d 39 30 45 45 2d 36 36 36 35 37 37 36 36 30 30 33 30 7d } //00 00  {DEDFF624-3CCB-11D9-90EE-666577660030}
	condition:
		any of ($a_*)
 
}