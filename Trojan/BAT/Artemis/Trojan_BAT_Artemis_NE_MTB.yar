
rule Trojan_BAT_Artemis_NE_MTB{
	meta:
		description = "Trojan:BAT/Artemis.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 04 00 00 06 28 07 00 00 06 6f 0e 00 00 0a 2a } //5
		$a_01_1 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f 12 00 00 0a 08 17 58 0c 08 02 8e 69 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}