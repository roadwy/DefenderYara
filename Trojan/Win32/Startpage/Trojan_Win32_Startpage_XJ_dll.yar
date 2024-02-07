
rule Trojan_Win32_Startpage_XJ_dll{
	meta:
		description = "Trojan:Win32/Startpage.XJ!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 76 6f 6c 37 37 37 2e 63 6f 6d 2f 3f } //01 00  .vol777.com/?
		$a_03_1 = {42 53 42 2e 65 78 65 90 01 09 61 75 74 6f 72 75 6e 2e 69 6e 66 90 01 09 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 42 53 42 2e 65 78 65 90 00 } //01 00 
		$a_01_2 = {00 5c b8 c4 b1 e4 c4 e3 b5 c4 d2 bb c9 fa 2e 75 72 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}