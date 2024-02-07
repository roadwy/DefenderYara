
rule Trojan_Win32_Detrahere_H{
	meta:
		description = "Trojan:Win32/Detrahere.H,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 56 43 56 4d 58 7b 37 32 43 45 38 44 42 30 2d 36 45 42 36 2d 34 43 32 34 2d 39 32 45 38 2d 41 30 37 42 37 37 41 32 32 39 46 38 7d } //01 00  SVCVMX{72CE8DB0-6EB6-4C24-92E8-A07B77A229F8}
		$a_01_1 = {45 3a 5c 63 65 66 5f 32 35 32 36 5c 64 6f 77 6e 6c 6f 61 64 5c 63 68 72 6f 6d 69 75 6d 5c 73 72 63 5c 6f 75 74 5c 52 65 6c 65 61 73 65 5c 77 69 6e 6c 74 63 2e 65 78 65 2e 70 64 62 } //01 00  E:\cef_2526\download\chromium\src\out\Release\winltc.exe.pdb
		$a_01_2 = {53 00 4d 00 41 00 52 00 54 00 53 00 4f 00 46 00 54 00 20 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 73 00 76 00 63 00 76 00 6d 00 78 00 } //00 00  SMARTSOFT Copyright (C) svcvmx
	condition:
		any of ($a_*)
 
}