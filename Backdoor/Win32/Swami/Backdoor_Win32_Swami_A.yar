
rule Backdoor_Win32_Swami_A{
	meta:
		description = "Backdoor:Win32/Swami.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 05 00 "
		
	strings :
		$a_03_0 = {8a 44 31 ff 8a 14 31 32 c2 8a d0 c0 ea 90 01 01 c0 e0 90 01 01 0a d0 88 14 31 49 75 90 01 01 8a 06 8a 4c 24 90 01 01 32 c1 8a c8 c0 e9 90 01 01 c0 e0 90 01 01 0a c8 88 0e 90 00 } //01 00 
		$a_01_1 = {2f 69 6d 2f 6c 69 6e 75 78 2e 70 68 70 } //01 00  /im/linux.php
		$a_01_2 = {2f 69 6d 2f 73 6f 6c 61 72 69 73 2e 70 68 70 } //01 00  /im/solaris.php
		$a_01_3 = {2f 69 6d 2f 66 72 65 65 62 73 64 2e 70 68 70 } //01 00  /im/freebsd.php
		$a_01_4 = {73 79 73 77 6d 69 2e 65 78 65 } //01 00  syswmi.exe
		$a_01_5 = {2f 63 67 69 2d 62 69 6e 2f 6d 6d 6c 6f 67 69 6e 2e 63 67 69 } //01 00  /cgi-bin/mmlogin.cgi
		$a_01_6 = {73 76 63 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}