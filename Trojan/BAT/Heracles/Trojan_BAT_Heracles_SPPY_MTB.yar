
rule Trojan_BAT_Heracles_SPPY_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 1f 4d 5d 6f 90 01 03 0a d2 61 d2 81 90 01 03 01 08 17 58 0c 08 07 17 59 33 d3 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}