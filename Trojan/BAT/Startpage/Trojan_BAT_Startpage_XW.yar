
rule Trojan_BAT_Startpage_XW{
	meta:
		description = "Trojan:BAT/Startpage.XW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 75 72 6c 73 5f 74 6f 5f 72 65 73 74 6f 72 65 5f 6f 6e 5f 73 74 61 72 74 75 70 22 3a 20 5b 20 22 68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 74 72 2f 22 20 5d } //01 00 
		$a_01_1 = {22 73 74 61 72 74 75 70 5f 6c 69 73 74 22 3a 20 5b 20 31 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 74 72 2f 22 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 22 20 5d } //01 00 
		$a_01_2 = {22 6c 61 73 74 5f 70 72 6f 6d 70 74 65 64 5f 67 6f 6f 67 6c 65 5f 75 72 6c 22 3a 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 74 72 2f 22 2c } //00 00 
	condition:
		any of ($a_*)
 
}