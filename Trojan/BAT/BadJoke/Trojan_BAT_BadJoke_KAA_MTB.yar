
rule Trojan_BAT_BadJoke_KAA_MTB{
	meta:
		description = "Trojan:BAT/BadJoke.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 11 07 61 1f 0a 63 61 5a 11 07 5a d2 9c 11 07 17 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}