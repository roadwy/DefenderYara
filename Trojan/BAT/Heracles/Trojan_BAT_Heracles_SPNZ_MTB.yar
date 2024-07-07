
rule Trojan_BAT_Heracles_SPNZ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 5d 91 11 09 61 13 0a 07 11 07 08 5d 91 13 0b 11 0a 11 0b 20 00 01 00 00 58 59 13 0c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}