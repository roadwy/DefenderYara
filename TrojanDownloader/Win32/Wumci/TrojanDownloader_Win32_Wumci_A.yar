
rule TrojanDownloader_Win32_Wumci_A{
	meta:
		description = "TrojanDownloader:Win32/Wumci.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 03 00 "
		
	strings :
		$a_01_0 = {48 4b 43 55 5e 73 6f 66 74 77 61 72 65 5c 78 66 6c 6f 63 6b } //03 00  HKCU^software\xflock
		$a_03_1 = {68 02 00 00 80 68 90 01 02 40 00 ff 35 90 01 03 00 c3 90 00 } //02 00 
		$a_01_2 = {66 33 c9 8b 4d } //02 00 
		$a_01_3 = {32 ed 8b 4d } //02 00 
		$a_01_4 = {62 74 73 00 } //01 00  瑢s
		$a_01_5 = {43 68 6b 44 73 6b 33 32 } //01 00  ChkDsk32
		$a_01_6 = {68 74 74 70 3a 2f 2f 67 65 74 79 6f 75 6e 65 65 64 2e 63 6f 6d 2f 72 2e 70 68 70 3f 77 6d 3d } //01 00  http://getyouneed.com/r.php?wm=
		$a_01_7 = {67 65 74 73 6f 66 74 2e 70 68 70 3f 69 64 3d } //00 00  getsoft.php?id=
	condition:
		any of ($a_*)
 
}