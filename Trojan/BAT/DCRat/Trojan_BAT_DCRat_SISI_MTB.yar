
rule Trojan_BAT_DCRat_SISI_MTB{
	meta:
		description = "Trojan:BAT/DCRat.SISI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 8d 24 00 00 01 13 04 7e ?? ?? ?? 04 02 1a 58 11 04 16 08 28 12 00 00 0a 28 56 00 00 0a 11 04 16 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}