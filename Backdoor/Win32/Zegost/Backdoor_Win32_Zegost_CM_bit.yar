
rule Backdoor_Win32_Zegost_CM_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CM!bit,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 09 00 00 0a 00 "
		
	strings :
		$a_03_0 = {7e 11 8a 14 01 80 c2 90 01 01 80 f2 90 01 01 88 14 01 41 3b ce 7c ef 90 00 } //03 00 
		$a_01_1 = {4c 6f 61 64 65 72 2e 64 6c 6c 00 44 61 74 61 } //02 00 
		$a_01_2 = {5c 5c 2e 5c 64 68 77 72 74 34 } //02 00  \\.\dhwrt4
		$a_01_3 = {51 51 47 61 6d 65 5c 78 78 2e 64 61 74 } //01 00  QQGame\xx.dat
		$a_01_4 = {49 20 61 6d 20 76 69 72 75 73 21 20 46 75 63 6b 20 79 6f 75 } //01 00  I am virus! Fuck you
		$a_01_5 = {43 4f 4d 53 50 45 43 00 5c 53 6f 75 67 6f 75 2e 6b 65 79 } //01 00 
		$a_01_6 = {5b 42 61 63 6b 73 70 61 63 65 5d 00 5b 43 61 70 73 20 4c 6f 63 6b 5d } //01 00 
		$a_01_7 = {33 36 30 73 64 2e 65 78 65 } //01 00  360sd.exe
		$a_01_8 = {5c 5c 2e 5c 50 48 59 53 49 43 41 4c 44 52 49 56 45 30 } //00 00  \\.\PHYSICALDRIVE0
		$a_00_9 = {5d 04 00 00 f0 } //cd 03 
	condition:
		any of ($a_*)
 
}