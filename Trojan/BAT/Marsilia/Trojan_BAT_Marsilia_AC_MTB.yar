
rule Trojan_BAT_Marsilia_AC_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 07 16 08 6e 28 90 01 03 0a 07 8e 69 28 90 01 03 0a 00 7e 12 00 00 0a 0d 16 13 04 7e 12 00 00 0a 13 05 16 16 08 11 05 16 12 04 28 90 01 03 06 0d 09 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}