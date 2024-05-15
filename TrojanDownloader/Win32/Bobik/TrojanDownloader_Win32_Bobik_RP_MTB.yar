
rule TrojanDownloader_Win32_Bobik_RP_MTB{
	meta:
		description = "TrojanDownloader:Win32/Bobik.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,42 00 42 00 09 00 00 14 00 "
		
	strings :
		$a_01_0 = {74 69 6d 65 62 6f 73 73 70 72 6f 2d 73 65 74 75 70 2e 65 78 65 } //14 00  timebosspro-setup.exe
		$a_01_1 = {4e 69 63 65 6b 69 74 2e 54 69 6d 65 42 6f 73 73 2e 46 6f 72 6d 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //14 00  Nicekit.TimeBoss.FormMain.resources
		$a_01_2 = {54 00 69 00 6d 00 65 00 20 00 42 00 6f 00 73 00 73 00 20 00 50 00 72 00 6f 00 } //05 00  Time Boss Pro
		$a_01_3 = {68 00 74 00 24 00 2f 00 6e 00 69 00 63 00 36 00 6f 00 61 00 64 00 2f 00 6e 00 65 00 77 00 2f 00 } //05 00  ht$/nic6oad/new/
		$a_01_4 = {68 00 74 00 24 00 2f 00 6e 00 69 00 63 00 65 00 6b 00 69 00 23 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 6e 00 65 00 77 00 2f 00 } //05 00  ht$/niceki#wnload/new/
		$a_01_5 = {68 00 74 00 24 00 2f 00 6e 00 69 00 63 00 65 00 6b 00 69 00 31 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 6e 00 65 00 77 00 2f 00 } //05 00  ht$/niceki1wnload/new/
		$a_01_6 = {68 00 74 00 24 00 2f 00 6e 00 69 00 63 00 23 00 6f 00 61 00 64 00 2f 00 6e 00 65 00 77 00 2f 00 } //01 00  ht$/nic#oad/new/
		$a_01_7 = {65 00 6b 00 69 00 74 00 2e 00 72 00 75 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 } //01 00  ekit.ru/downl
		$a_01_8 = {74 00 2e 00 72 00 75 00 2f 00 64 00 6f 00 } //00 00  t.ru/do
	condition:
		any of ($a_*)
 
}