
rule Trojan_BAT_FormBook_ALD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ALD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 7e 90 01 03 04 06 28 90 01 03 06 d2 9c 00 09 17 58 90 00 } //01 00 
		$a_01_1 = {53 00 61 00 76 00 61 00 73 00 2e 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 } //01 00 
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}