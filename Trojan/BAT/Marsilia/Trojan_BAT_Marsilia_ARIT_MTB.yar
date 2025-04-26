
rule Trojan_BAT_Marsilia_ARIT_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.ARIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 17 d6 0b 07 19 d6 0b 07 18 da 0b 07 20 a0 86 01 00 33 ec 16 0c 08 17 d6 0c 17 0d 09 1b d6 1b d6 18 d6 0d 08 20 88 13 00 00 33 06 08 17 d6 17 da 0c 09 09 08 d6 1b da d6 0d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}