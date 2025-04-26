
rule Trojan_BAT_Rozena_AT_MTB{
	meta:
		description = "Trojan:BAT/Rozena.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 13 07 2b 36 09 11 07 07 11 07 91 1f 42 61 d2 9c 09 11 07 07 11 07 91 1f 43 61 d2 9c 09 11 07 07 11 07 91 1f 44 61 d2 9c 09 11 07 07 11 07 91 1f 45 61 d2 9c 11 07 1a 58 13 07 11 07 08 32 c5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}