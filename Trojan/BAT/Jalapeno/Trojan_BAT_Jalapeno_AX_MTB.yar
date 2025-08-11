
rule Trojan_BAT_Jalapeno_AX_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 09 08 07 5a 8d ?? ?? 00 01 13 0a 02 09 11 05 07 5a 08 5a 6a 58 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}