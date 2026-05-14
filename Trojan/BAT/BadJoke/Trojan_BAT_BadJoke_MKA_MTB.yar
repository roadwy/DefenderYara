
rule Trojan_BAT_BadJoke_MKA_MTB{
	meta:
		description = "Trojan:BAT/BadJoke.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 64 20 e7 03 00 00 6f 0e 00 00 0a 8c 05 00 00 01 72 af 01 00 70 28 0f 00 00 0a 28 10 00 00 0a 13 05 11 05 11 04 28 11 00 00 0a 00 72 b9 01 00 70 11 05 28 04 00 00 0a 00 72 fd 01 00 70 } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}