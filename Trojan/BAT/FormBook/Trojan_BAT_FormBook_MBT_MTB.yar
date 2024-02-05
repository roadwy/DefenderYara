
rule Trojan_BAT_FormBook_MBT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 44 7d 35 41 7d 39 21 7d 26 7d 21 33 7d 26 7d 26 7d 26 7d 21 34 7d 26 7d 26 7d 26 7d 46 46 7d 46 46 7d 26 7d 26 7d 42 38 7d 26 7d 26 7d 26 7d 26 7d 26 7d 26 7d 26 7d 34 21 7d 26 7d 26 7d } //01 00 
		$a_01_1 = {20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 50 00 21 00 65 00 73 00 2e 00 57 00 68 00 21 00 74 00 65 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 } //00 00 
	condition:
		any of ($a_*)
 
}