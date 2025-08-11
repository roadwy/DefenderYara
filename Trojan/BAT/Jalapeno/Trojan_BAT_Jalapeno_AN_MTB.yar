
rule Trojan_BAT_Jalapeno_AN_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 0d 28 5b 00 00 0a 09 6f 5c 00 00 0a 07 1f 7d 30 10 08 20 80 00 00 00 07 60 d2 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}