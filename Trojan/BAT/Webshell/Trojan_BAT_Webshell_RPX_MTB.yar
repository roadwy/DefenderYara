
rule Trojan_BAT_Webshell_RPX_MTB{
	meta:
		description = "Trojan:BAT/Webshell.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 00 67 00 2f 00 62 00 6f 00 74 00 74 00 6f 00 6d 00 2e 00 61 00 73 00 63 00 78 00 } //01 00  3g/bottom.ascx
		$a_01_1 = {33 00 67 00 2f 00 73 00 6f 00 6c 00 75 00 74 00 69 00 74 00 6f 00 70 00 2e 00 61 00 73 00 70 00 78 00 } //01 00  3g/solutitop.aspx
		$a_01_2 = {4f 00 47 00 56 00 6c 00 59 00 6a 00 55 00 34 00 4e 00 44 00 45 00 7a 00 4d 00 6a 00 59 00 7a 00 4d 00 51 00 3d 00 3d 00 } //01 00  OGVlYjU4NDEzMjYzMQ==
		$a_01_3 = {77 00 77 00 77 00 2e 00 67 00 6f 00 76 00 2e 00 63 00 6e 00 } //01 00  www.gov.cn
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_5 = {45 6e 63 6f 64 69 6e 67 } //01 00  Encoding
		$a_01_6 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_01_7 = {43 6f 6e 63 61 74 } //01 00  Concat
		$a_01_8 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}