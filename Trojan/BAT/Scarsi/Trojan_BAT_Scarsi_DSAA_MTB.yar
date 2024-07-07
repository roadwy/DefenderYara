
rule Trojan_BAT_Scarsi_DSAA_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.DSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 1f 00 07 09 8f 90 01 01 00 00 01 13 04 11 04 11 04 47 02 09 6a 06 6e 5d d4 91 61 d2 52 00 09 17 d6 0d 09 08 fe 02 16 fe 01 13 05 11 05 2d d4 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}