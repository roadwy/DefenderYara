
rule Trojan_BAT_Injuke_RJAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.RJAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 06 02 06 91 66 d2 9c 02 06 8f 22 00 00 01 25 71 22 00 00 01 20 84 00 00 00 59 d2 81 22 00 00 01 02 06 8f 22 00 00 01 25 71 22 00 00 01 1f 67 58 d2 81 22 00 00 01 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}