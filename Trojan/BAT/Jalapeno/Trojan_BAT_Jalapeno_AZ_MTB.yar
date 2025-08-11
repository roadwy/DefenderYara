
rule Trojan_BAT_Jalapeno_AZ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0b 1a 8d 06 00 00 01 0c 06 08 16 1a 6f 35 00 00 0a 1a 2e 06 73 54 00 00 0a 7a 06 16 73 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}