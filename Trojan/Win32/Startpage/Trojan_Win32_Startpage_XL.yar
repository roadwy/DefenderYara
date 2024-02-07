
rule Trojan_Win32_Startpage_XL{
	meta:
		description = "Trojan:Win32/Startpage.XL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 2e 66 72 65 65 73 68 69 70 69 6e 2e 69 6e 66 6f 3a 31 31 38 38 2f } //01 00  g.freeshipin.info:1188/
		$a_01_1 = {66 61 63 61 69 2e 6a 69 61 6e 6b 61 6e 67 6d 6d 2e 63 6f 6d 2f } //01 00  facai.jiankangmm.com/
		$a_01_2 = {00 bd a1 bf b5 6d 6d cd f8 00 } //01 00 
		$a_03_3 = {7b 45 33 43 31 42 43 37 30 2d 31 36 30 37 2d 34 33 42 44 2d 41 30 35 35 2d 41 43 42 34 42 46 38 44 42 41 90 01 02 7d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}