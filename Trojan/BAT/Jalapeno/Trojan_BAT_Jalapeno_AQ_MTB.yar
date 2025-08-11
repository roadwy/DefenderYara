
rule Trojan_BAT_Jalapeno_AQ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 0c 7e 89 00 00 04 02 4a 08 16 07 28 47 00 00 0a 03 08 04 73 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}