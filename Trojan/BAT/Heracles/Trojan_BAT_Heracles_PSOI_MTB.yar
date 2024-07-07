
rule Trojan_BAT_Heracles_PSOI_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSOI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 28 1d 00 00 0a 0a 73 90 01 03 0a 28 90 01 03 0a 72 01 00 00 70 6f 90 01 03 0a 28 90 01 03 0a 0b 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a 00 08 18 6f 90 01 03 0a 00 08 18 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}