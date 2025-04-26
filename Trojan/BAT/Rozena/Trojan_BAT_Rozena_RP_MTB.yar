
rule Trojan_BAT_Rozena_RP_MTB{
	meta:
		description = "Trojan:BAT/Rozena.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 11 0a 08 11 0a 91 11 04 11 0a 1f 20 5d 91 61 d2 9c 08 11 0a 08 11 0a 91 09 11 0a 1f 20 5d 91 61 d2 9c 11 0a 13 0b 11 0b 17 58 13 0a 11 0a 08 8e 69 32 cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}