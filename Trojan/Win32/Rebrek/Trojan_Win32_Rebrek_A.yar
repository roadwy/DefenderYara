
rule Trojan_Win32_Rebrek_A{
	meta:
		description = "Trojan:Win32/Rebrek.A,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0b 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {61 00 73 00 6b 00 74 00 67 00 74 00 } //01 00  asktgt
		$a_00_1 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //01 00  password
		$a_00_2 = {75 00 73 00 65 00 72 00 } //01 00  user
		$a_00_3 = {74 00 69 00 63 00 6b 00 65 00 74 00 } //01 00  ticket
		$a_00_4 = {64 00 6f 00 6d 00 61 00 69 00 6e 00 } //01 00  domain
		$a_00_5 = {2f 00 64 00 63 00 } //01 00  /dc
		$a_00_6 = {63 00 65 00 72 00 74 00 69 00 66 00 69 00 63 00 61 00 74 00 65 00 } //01 00  certificate
		$a_00_7 = {63 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 } //00 00  credentials
	condition:
		any of ($a_*)
 
}