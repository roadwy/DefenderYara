
rule Trojan_Win32_Starter_L{
	meta:
		description = "Trojan:Win32/Starter.L,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 53 6f 66 74 77 61 72 65 } //01 00  SOFTWARE\MSoftware
		$a_01_1 = {6b 69 6c 6c 61 6c 6c 2a 2a } //02 00  killall**
		$a_01_2 = {61 64 65 33 34 65 61 38 32 63 34 66 37 66 32 66 2e 6e 65 74 } //02 00  ade34ea82c4f7f2f.net
		$a_01_3 = {66 31 39 64 64 34 61 62 62 38 62 38 62 64 66 32 2e 63 6e } //02 00  f19dd4abb8b8bdf2.cn
		$a_01_4 = {37 39 65 63 62 66 31 63 33 61 36 63 37 36 62 38 2e 6e 65 74 } //01 00  79ecbf1c3a6c76b8.net
		$a_01_5 = {64 61 74 61 2e 63 67 69 } //01 00  data.cgi
		$a_01_6 = {67 65 74 2e 63 67 69 3f } //01 00  get.cgi?
		$a_01_7 = {6d 73 66 74 6c 64 72 2e 64 6c 6c } //01 00  msftldr.dll
		$a_01_8 = {6d 73 66 74 74 6d 70 2e 64 6c 6c } //01 00  msfttmp.dll
		$a_01_9 = {6d 73 66 74 74 6d 70 63 66 67 } //01 00  msfttmpcfg
		$a_01_10 = {6d 73 66 74 63 6f 72 65 2e 64 61 74 } //02 00  msftcore.dat
		$a_00_11 = {1e 21 89 10 ad 10 e2 80 3c 00 46 da ad 20 e2 1b 2c 92 ca } //00 00 
	condition:
		any of ($a_*)
 
}