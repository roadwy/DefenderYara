
rule Trojan_Linux_GitCredentials_A{
	meta:
		description = "Trojan:Linux/GitCredentials.A,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {00 67 00 69 00 74 00 20 90 03 08 0c 00 67 00 72 00 65 00 70 00 6c 00 6f 00 67 00 20 00 2d 00 53 00 20 90 00 } //01 00 
		$a_00_1 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //01 00  password
		$a_00_2 = {70 00 61 00 73 00 73 00 } //01 00  pass
		$a_00_3 = {70 00 77 00 } //01 00  pw
		$a_00_4 = {6b 00 65 00 79 00 } //00 00  key
	condition:
		any of ($a_*)
 
}