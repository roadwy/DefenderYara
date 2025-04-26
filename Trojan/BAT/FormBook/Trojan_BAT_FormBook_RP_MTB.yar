
rule Trojan_BAT_FormBook_RP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 7b 32 00 00 04 0f 01 28 47 00 00 0a 28 81 00 00 06 2a 00 13 30 05 00 1d 00 00 00 01 00 00 11 02 7b 38 00 00 04 16 02 7b 38 00 00 04 28 80 00 00 06 28 83 00 00 06 28 84 00 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}