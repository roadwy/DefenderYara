
rule Trojan_BAT_Zemsil_SF_MTB{
	meta:
		description = "Trojan:BAT/Zemsil.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 08 11 04 18 6f 0a 00 00 0a 1f 10 28 0b 00 00 0a 6f 0c 00 00 0a 11 04 18 58 13 04 11 04 08 6f 0d 00 00 0a 32 da } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}