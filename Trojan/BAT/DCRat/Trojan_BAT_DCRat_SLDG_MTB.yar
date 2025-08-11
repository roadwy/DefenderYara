
rule Trojan_BAT_DCRat_SLDG_MTB{
	meta:
		description = "Trojan:BAT/DCRat.SLDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 4d 00 00 0a 72 54 01 00 70 6f 4e 00 00 0a 0a 06 6f 4f 00 00 0a d4 8d 2a 00 00 01 0b 06 07 16 07 8e 69 6f 50 00 00 0a 26 28 51 00 00 0a 0c 08 28 52 00 00 0a 1f ?? 28 53 00 00 0a 6f 54 00 00 0a 6f 55 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}