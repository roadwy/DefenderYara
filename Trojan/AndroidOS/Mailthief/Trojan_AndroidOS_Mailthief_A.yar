
rule Trojan_AndroidOS_Mailthief_A{
	meta:
		description = "Trojan:AndroidOS/Mailthief.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 65 77 20 6d 65 73 73 61 67 65 21 2e 20 63 6f 6e 74 61 63 74 20 6e 61 6d 65 3a } //01 00  new message!. contact name:
		$a_01_1 = {69 73 20 4e 45 57 20 2d 3e 20 69 6e 73 65 72 74 } //00 00  is NEW -> insert
	condition:
		any of ($a_*)
 
}