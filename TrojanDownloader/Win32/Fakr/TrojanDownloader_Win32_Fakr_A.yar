
rule TrojanDownloader_Win32_Fakr_A{
	meta:
		description = "TrojanDownloader:Win32/Fakr.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 69 76 65 66 6c 6f 61 74 2e 63 6f 6d } //01 00  livefloat.com
		$a_01_1 = {2e 7a 65 72 6f 63 6c 65 61 72 2e 6e 65 74 } //05 00  .zeroclear.net
		$a_02_2 = {2f 63 6f 75 6e 74 2f 69 6e 73 74 90 03 0e 05 61 6c 6c 5f 63 6f 75 6e 74 2e 70 68 70 3f 2e 70 68 70 3f 90 00 } //04 00 
		$a_00_3 = {26 6b 69 6e 64 3d } //03 00  &kind=
		$a_03_4 = {5c 41 52 50 43 61 63 68 65 90 09 39 00 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 4d 61 6e 61 67 65 6d 65 6e 74 90 00 } //fb ff 
		$a_01_5 = {61 64 64 65 6e 64 75 6d 5c 73 69 64 65 62 61 72 5c } //00 00  addendum\sidebar\
	condition:
		any of ($a_*)
 
}