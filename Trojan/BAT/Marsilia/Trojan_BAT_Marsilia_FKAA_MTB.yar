
rule Trojan_BAT_Marsilia_FKAA_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.FKAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0b 2b 13 06 07 02 07 91 04 07 04 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 6a 03 32 e8 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}