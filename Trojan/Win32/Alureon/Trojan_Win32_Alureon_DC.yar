
rule Trojan_Win32_Alureon_DC{
	meta:
		description = "Trojan:Win32/Alureon.DC,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 38 53 52 54 00 } //01 00  㡈剓T
		$a_01_1 = {25 73 25 73 25 78 2e 74 6d 70 } //01 00  %s%s%x.tmp
		$a_01_2 = {5b 25 73 5d 20 46 69 6c 65 20 64 6f 77 6e 6c 6f 61 64 20 25 73 } //01 00  [%s] File download %s
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 41 6e 64 45 78 65 63 75 74 65 53 6f 66 74 53 74 72 69 6e 67 28 25 73 29 } //01 00  DownloadAndExecuteSoftString(%s)
		$a_01_4 = {4c 69 74 65 4c 6f 61 64 65 72 } //01 00  LiteLoader
		$a_01_5 = {54 44 4c 20 53 74 61 72 74 20 4d 75 74 65 78 20 64 65 74 65 63 74 65 64 } //01 00  TDL Start Mutex detected
		$a_01_6 = {4d 52 53 20 4c 6f 61 64 65 72 20 77 61 73 20 68 65 72 65 2e 2e 2e } //01 00  MRS Loader was here...
		$a_01_7 = {32 32 34 3b 6e 65 77 3b 00 68 74 74 70 3a 2f 2f } //03 00  ㈲㬴敮㭷栀瑴㩰⼯
		$a_03_8 = {8d 54 02 18 33 c0 3b de 76 35 55 89 54 24 0c 57 8b 74 24 10 6a 05 bf 90 01 04 59 33 ed f3 a6 74 10 83 44 24 10 28 40 3b c3 72 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}