
rule Trojan_BAT_FormBook_EVF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 43 00 48 00 47 00 50 00 41 00 38 00 45 00 41 00 46 00 38 00 53 00 41 00 42 00 43 00 38 00 58 00 5a 00 54 00 4e 00 4b 00 34 00 } //01 00 
		$a_03_1 = {5d 91 0a 06 90 01 05 03 04 5d 90 01 05 61 0b 2b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}