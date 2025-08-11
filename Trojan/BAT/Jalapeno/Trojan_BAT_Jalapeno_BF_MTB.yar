
rule Trojan_BAT_Jalapeno_BF_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 0d 08 09 16 09 8e 69 6f 23 00 00 0a 26 09 16 28 24 00 00 0a 13 04 08 16 73 25 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}