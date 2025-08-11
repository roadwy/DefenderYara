
rule Trojan_BAT_Heracles_EAED_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EAED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 06 02 28 45 00 00 06 06 02 28 45 00 00 06 8e 69 5d 91 03 06 91 61 d2 9c 06 17 58 0a 06 03 8e 69 32 dd } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}