
rule Trojan_BAT_Zusy_EM_MTB{
	meta:
		description = "Trojan:BAT/Zusy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 09 2b 30 11 06 11 09 94 11 06 11 09 17 58 94 31 1c 11 06 11 09 94 13 0a 11 06 11 09 11 06 11 09 17 58 94 9e 11 06 11 09 17 58 11 0a 9e 11 09 17 58 13 09 11 09 11 06 8e 69 17 59 11 08 59 32 c3 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}