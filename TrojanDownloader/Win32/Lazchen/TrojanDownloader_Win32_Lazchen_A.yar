
rule TrojanDownloader_Win32_Lazchen_A{
	meta:
		description = "TrojanDownloader:Win32/Lazchen.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {79 77 59 41 41 41 3d 3d 6e 37 6c 73 76 30 21 78 } //1 ywYAAA==n7lsv0!x
		$a_01_1 = {62 42 21 53 50 38 2a 23 57 44 4d 43 41 41 3d 3d } //1 bB!SP8*#WDMCAA==
		$a_01_2 = {50 46 60 45 6a 31 44 6b 61 4f 6b 09 6f 52 77 72 } //1 䙐䕠ㅪ歄佡५副牷
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}