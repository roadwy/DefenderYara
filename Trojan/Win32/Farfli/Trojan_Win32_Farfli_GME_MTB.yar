
rule Trojan_Win32_Farfli_GME_MTB{
	meta:
		description = "Trojan:Win32/Farfli.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b e8 c7 45 90 01 01 43 3a 2f 2f c7 45 90 01 01 55 73 65 72 c7 45 90 01 01 73 2f 2f 50 c7 45 90 01 01 75 62 6c 69 c7 45 90 01 01 63 2f 2f 44 c7 45 90 01 01 6f 77 6e 6c c7 45 90 01 01 6f 61 64 73 66 c7 45 90 01 01 2f 2f 90 00 } //01 00 
		$a_01_1 = {42 72 6f 77 73 65 72 43 6f 6e 66 69 67 46 69 6c 65 49 6e 66 6f 41 } //00 00  BrowserConfigFileInfoA
	condition:
		any of ($a_*)
 
}