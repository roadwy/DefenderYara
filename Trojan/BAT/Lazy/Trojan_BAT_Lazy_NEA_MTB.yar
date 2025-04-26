
rule Trojan_BAT_Lazy_NEA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 04 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 02 0c 06 6f ?? 00 00 0a 08 16 08 8e 69 6f ?? 00 00 0a 13 05 de 25 07 2b d2 09 2b d1 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}