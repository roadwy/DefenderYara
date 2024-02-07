
rule TrojanDownloader_Win32_Radrawtion_A{
	meta:
		description = "TrojanDownloader:Win32/Radrawtion.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 74 0c 14 90 01 01 8d 44 24 14 83 c1 01 8d 70 01 8a 10 83 c0 01 84 d2 75 f7 2b c6 3b c8 72 e2 90 00 } //01 00 
		$a_01_1 = {6d 71 71 75 3f 2a 2a 72 72 72 2b 6f 6f 64 6b 63 6c 69 60 2b 66 6a 2b 6e 77 2a } //02 00  mqqu?**rrr+oodkcli`+fj+nw*
		$a_11_2 = {74 74 70 3a 2f 2f 77 77 77 2e 6a 6a 61 6e 66 69 6c 65 2e 63 6f 2e 6b 72 2f 01 } //00 12 
		$a_70_3 = {61 } //64 71  a
		$a_2a_4 = {6c 6b 71 77 64 77 6a 64 61 2a 02 00 12 11 75 70 64 61 74 65 2f 77 69 6e 74 72 61 72 6f 61 64 2f 02 00 0e 01 43 77 69 6e 74 72 61 72 6f 61 64 41 70 70 02 00 0b 01 77 69 6e 74 72 61 72 6f 61 64 00 01 00 17 01 68 cc ea 43 00 51 ff 15 18 90 43 00 68 d0 07 00 00 ff 15 bc 92 43 00 00 00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}