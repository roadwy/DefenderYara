
rule Trojan_Win32_Rebrek_B{
	meta:
		description = "Trojan:Win32/Rebrek.B,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0b 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 61 00 73 00 74 00 } //01 00  kerberoast
		$a_00_1 = {63 00 72 00 65 00 64 00 75 00 73 00 65 00 72 00 } //01 00  creduser
		$a_00_2 = {2f 00 73 00 70 00 6e 00 } //01 00  /spn
		$a_00_3 = {73 00 69 00 6d 00 70 00 6c 00 65 00 20 00 } //01 00  simple 
		$a_00_4 = {74 00 69 00 63 00 6b 00 65 00 74 00 } //01 00  ticket
		$a_00_5 = {6c 00 64 00 61 00 70 00 66 00 69 00 6c 00 74 00 65 00 72 00 } //00 00  ldapfilter
	condition:
		any of ($a_*)
 
}