
rule Trojan_BAT_Zusy_GMY_MTB{
	meta:
		description = "Trojan:BAT/Zusy.GMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 11 0a 20 90 01 04 58 61 16 58 38 90 01 04 08 6f 90 01 03 06 2c 08 20 90 01 04 25 2b 06 20 90 01 04 25 26 11 0a 20 90 01 04 58 61 16 58 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}