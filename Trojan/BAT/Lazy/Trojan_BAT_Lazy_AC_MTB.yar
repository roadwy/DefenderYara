
rule Trojan_BAT_Lazy_AC_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 64 00 00 01 0d 11 06 20 b3 e5 26 d9 61 13 0a 38 1f 01 00 00 20 21 3f ?? da 13 06 11 06 20 32 97 ac 51 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}