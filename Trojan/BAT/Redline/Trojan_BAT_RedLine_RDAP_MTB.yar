
rule Trojan_BAT_RedLine_RDAP_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {39 66 33 35 66 66 65 38 2d 33 31 65 37 2d 34 39 38 32 2d 39 38 65 35 2d 39 36 63 61 34 63 63 35 30 66 62 38 } //1 9f35ffe8-31e7-4982-98e5-96ca4cc50fb8
		$a_01_1 = {54 73 6e 71 67 64 6a 6b 63 65 } //1 Tsnqgdjkce
		$a_01_2 = {41 00 6e 00 6d 00 78 00 71 00 62 00 6e 00 70 00 6a 00 6e 00 } //1 Anmxqbnpjn
		$a_01_3 = {41 00 6e 00 6d 00 78 00 71 00 62 00 6e 00 70 00 6a 00 6e 00 2e 00 53 00 6b 00 62 00 65 00 61 00 66 00 69 00 72 00 } //1 Anmxqbnpjn.Skbeafir
		$a_01_4 = {50 00 69 00 77 00 78 00 62 00 72 00 66 00 64 00 62 00 65 00 61 00 62 00 66 00 6e 00 7a 00 62 00 6b 00 } //1 Piwxbrfdbeabfnzbk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}