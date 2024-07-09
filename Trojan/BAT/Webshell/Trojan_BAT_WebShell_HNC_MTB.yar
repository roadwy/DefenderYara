
rule Trojan_BAT_WebShell_HNC_MTB{
	meta:
		description = "Trojan:BAT/WebShell.HNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {46 61 73 74 4f 62 6a 65 63 74 46 61 63 74 6f 72 79 5f 61 70 70 5f 77 65 62 5f [0-30] 5f 5f 41 53 50 00 } //1
		$a_01_1 = {00 09 70 00 61 00 73 00 73 00 00 03 2d 00 01 01 00 0f 70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 00 09 4c 00 6f 00 61 00 64 } //1
		$a_01_2 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 } //1 䘀潲䉭獡㙥匴牴湩g
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}