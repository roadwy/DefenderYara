
rule Trojan_BAT_FormBook_AGCG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AGCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 11 08 06 07 06 9a 1f 10 28 90 01 03 0a 9c 06 17 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}