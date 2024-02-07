
rule TrojanDownloader_Win32_Zlob_gen_AAA{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AAA,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 63 5c 73 76 63 68 3b 74 5c } //01 00  tc\svch;t\
		$a_01_1 = {72 62 2b 74 61 73 6b 6d 67 72 56 } //01 00  rb+taskmgrV
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 72 61 62 62 69 74 73 61 66 65 2e 63 6e 2f 74 65 73 74 2e 65 78 65 } //01 00  http://www.rabbitsafe.cn/test.exe
		$a_01_3 = {5c 64 72 69 76 65 72 73 5c 73 76 63 68 6f 73 74 } //00 00  \drivers\svchost
	condition:
		any of ($a_*)
 
}