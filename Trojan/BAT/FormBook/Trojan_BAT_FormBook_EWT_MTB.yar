
rule Trojan_BAT_FormBook_EWT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EWT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 74 00 72 00 00 09 69 00 6e 00 67 00 31 } //01 00 
		$a_01_1 = {86 06 20 00 86 06 20 00 86 06 20 00 86 06 20 00 86 06 } //01 00 
		$a_01_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00  GetExportedTypes
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}