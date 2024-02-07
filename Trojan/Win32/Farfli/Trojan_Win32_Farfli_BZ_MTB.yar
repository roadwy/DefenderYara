
rule Trojan_Win32_Farfli_BZ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 44 24 20 8a 14 29 02 c3 2a d0 88 14 29 41 3b ce 7c } //01 00 
		$a_01_1 = {63 3a 5c 25 73 2e 65 78 65 } //01 00  c:\%s.exe
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 32 26 25 73 } //01 00  cmd.exe /c ping 127.0.0.1 -n 2&%s
		$a_01_3 = {63 3a 5c 77 69 73 65 6d 61 6e 2e 65 78 65 } //01 00  c:\wiseman.exe
		$a_01_4 = {65 6b 69 6d 68 75 71 63 72 6f 61 6e 66 6c 76 7a 67 64 6a 74 78 79 70 73 77 62 } //00 00  ekimhuqcroanflvzgdjtxypswb
	condition:
		any of ($a_*)
 
}