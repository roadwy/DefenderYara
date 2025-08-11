
rule Trojan_BAT_Jalapeno_BH_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 0a 38 09 00 00 00 03 06 16 07 6f 59 00 00 0a 02 06 16 06 8e 69 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}