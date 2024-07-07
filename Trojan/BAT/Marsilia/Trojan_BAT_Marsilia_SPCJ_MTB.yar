
rule Trojan_BAT_Marsilia_SPCJ_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.SPCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 8e 69 20 90 01 03 00 1f 40 28 90 01 03 06 0d 7e 90 01 03 0a 13 90 01 01 07 7b 90 01 03 04 09 06 06 8e 69 12 90 01 01 28 90 01 03 06 2c 1e 16 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}