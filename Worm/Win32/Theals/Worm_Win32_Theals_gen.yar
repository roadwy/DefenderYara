
rule Worm_Win32_Theals_gen{
	meta:
		description = "Worm:Win32/Theals.gen,SIGNATURE_TYPE_PEHSTR_EXT,18 00 0b 00 10 00 00 0a 00 "
		
	strings :
		$a_02_0 = {e8 00 00 00 00 5a 81 ea 90 01 02 41 00 89 9a 90 01 01 10 40 00 89 b2 90 01 01 10 40 00 89 ba 90 01 01 10 40 00 89 aa 90 01 01 10 40 00 8b da 2b c0 64 8b 38 48 8b c8 f2 af af 8b 07 66 2b c0 66 81 38 4d 5a 74 07 2d 00 00 01 00 eb f2 89 83 90 01 01 10 40 00 90 00 } //0a 00 
		$a_01_1 = {e8 0b 00 00 00 76 69 63 74 69 6d 2e 65 78 65 00 } //02 00 
		$a_01_2 = {e8 0d 00 00 00 61 64 76 61 70 69 33 32 2e 64 6c 6c 00 } //02 00 
		$a_01_3 = {e8 0b 00 00 00 75 73 65 72 33 32 2e 64 6c 6c 00 } //01 00 
		$a_01_4 = {73 74 65 61 6c 74 68 2e 73 68 61 72 65 64 2e 64 6c 6c } //01 00  stealth.shared.dll
		$a_01_5 = {63 3a 5c 73 74 65 61 6c 74 68 2e 77 6f 72 6d 2e 65 78 65 } //01 00  c:\stealth.worm.exe
		$a_01_6 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 63 3a 5c 73 74 65 61 6c 74 68 2e 77 6f 72 6d 2e 65 78 65 } //01 00  explorer.exe c:\stealth.worm.exe
		$a_01_7 = {73 74 65 61 6c 74 68 2e 62 73 7a 69 70 2e 64 6c 6c } //01 00  stealth.bszip.dll
		$a_01_8 = {73 74 65 61 6c 74 68 2e 64 63 6f 6d 2e 65 78 65 } //01 00  stealth.dcom.exe
		$a_01_9 = {73 74 65 61 6c 74 68 2e 64 64 6f 73 2e 65 78 65 } //01 00  stealth.ddos.exe
		$a_01_10 = {73 74 65 61 6c 74 68 2e 69 6e 6a 65 63 74 6f 72 2e 65 78 65 } //01 00  stealth.injector.exe
		$a_01_11 = {73 74 65 61 6c 74 68 2e 73 74 61 74 2e 65 78 65 } //01 00  stealth.stat.exe
		$a_01_12 = {73 74 65 61 6c 74 68 2e 73 70 61 6d 2e 65 78 65 } //01 00  stealth.spam.exe
		$a_01_13 = {73 74 65 61 6c 74 68 2e 77 6d 2e 65 78 65 } //01 00  stealth.wm.exe
		$a_01_14 = {73 74 65 61 6c 74 68 2e 65 78 65 } //01 00  stealth.exe
		$a_01_15 = {28 78 29 20 32 30 30 35 20 5a 30 4d 42 69 45 } //00 00  (x) 2005 Z0MBiE
	condition:
		any of ($a_*)
 
}