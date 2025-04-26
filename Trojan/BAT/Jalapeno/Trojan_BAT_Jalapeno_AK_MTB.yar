
rule Trojan_BAT_Jalapeno_AK_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 13 04 16 13 08 2b 26 11 07 11 05 11 08 1a 11 04 16 6f 5d 00 00 0a 26 11 08 1a d6 13 08 08 11 04 16 11 07 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}