
rule Trojan_BAT_Njrat_MBID_MTB{
	meta:
		description = "Trojan:BAT/Njrat.MBID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 02 11 05 91 08 61 06 07 91 61 b4 9c 07 03 6f 90 01 01 00 00 0a 17 da fe 01 13 07 11 07 2c 04 16 0b 2b 05 90 00 } //1
		$a_01_1 = {39 66 62 36 62 66 36 36 65 39 37 61 } //1 9fb6bf66e97a
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}