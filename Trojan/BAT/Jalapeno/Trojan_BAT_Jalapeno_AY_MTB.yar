
rule Trojan_BAT_Jalapeno_AY_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 25 16 03 d2 9c 0b 02 07 28 0c 00 00 2b 28 0d 00 00 2b 0c 08 10 00 02 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}