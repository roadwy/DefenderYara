
rule Trojan_BAT_FormBook_CW_MTB{
	meta:
		description = "Trojan:BAT/FormBook.CW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {02 1f 0a 16 8d 90 01 01 00 00 01 28 90 01 01 00 00 0a a5 90 00 } //01 00 
		$a_01_1 = {56 4d 45 6e 74 72 79 } //01 00  VMEntry
		$a_01_2 = {4b 6f 69 56 4d } //00 00  KoiVM
	condition:
		any of ($a_*)
 
}