
rule Trojan_BAT_NjRAT_PSUF_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PSUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 20 e8 03 00 00 28 90 01 01 00 00 0a 00 72 63 00 00 70 0c 08 7e 02 00 00 04 28 90 01 01 00 00 06 0d 09 2c 0d 00 7e 02 00 00 04 28 90 01 01 00 00 0a 26 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}