
rule Trojan_Win32_Pixsteal_B{
	meta:
		description = "Trojan:Win32/Pixsteal.B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 06 00 00 04 00 "
		
	strings :
		$a_03_0 = {66 6f 72 20 2f 72 20 90 01 01 3a 5c 20 25 78 20 69 6e 90 02 09 2a 2e 6a 70 67 90 02 13 64 6f 20 63 6f 70 79 20 2f 79 20 25 78 20 43 3a 5c 90 00 } //03 00 
		$a_00_1 = {40 67 61 72 69 74 72 61 6e 73 2e 63 6c } //02 00  @garitrans.cl
		$a_01_2 = {36 36 2e 37 2e 31 39 38 2e 32 34 30 } //01 00  66.7.198.240
		$a_00_3 = {57 69 6e 52 41 52 2e 65 78 65 20 61 20 25 78 20 2e 44 6f 77 6e 6c 6f 61 64 2e 65 78 65 } //01 00  WinRAR.exe a %x .Download.exe
		$a_00_4 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 64 69 73 61 62 6c 65 } //01 00  netsh firewall set opmode disable
		$a_00_5 = {63 3a 5c 25 64 2d 66 69 6c 65 25 64 2e 62 6d 70 } //00 00  c:\%d-file%d.bmp
		$a_00_6 = {5d 04 00 } //00 d5 
	condition:
		any of ($a_*)
 
}