
rule Trojan_BAT_Remcos_PSUR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.PSUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 57 0a 00 06 20 03 00 00 00 38 b5 ff ff ff 11 08 11 08 28 58 0a 00 06 11 08 28 59 0a 00 06 6f 5f 00 00 0a 13 04 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}