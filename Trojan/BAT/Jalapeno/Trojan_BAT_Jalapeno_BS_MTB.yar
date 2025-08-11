
rule Trojan_BAT_Jalapeno_BS_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 13 05 1f fe 66 13 06 2b 8d 09 1f f8 65 19 63 33 5b 20 3e 93 c3 0d 20 3c 93 c3 0d 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}