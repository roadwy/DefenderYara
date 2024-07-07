
rule Trojan_BAT_Heracles_PSSP_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 72 cf 02 00 70 28 90 01 01 00 00 0a 13 04 28 90 01 01 00 00 0a 72 3d 03 00 70 08 09 07 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 05 11 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}