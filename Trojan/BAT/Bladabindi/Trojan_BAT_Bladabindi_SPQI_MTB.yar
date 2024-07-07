
rule Trojan_BAT_Bladabindi_SPQI_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SPQI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 08 28 90 01 03 06 58 0c 08 02 8e 69 3f e0 ff ff ff 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}