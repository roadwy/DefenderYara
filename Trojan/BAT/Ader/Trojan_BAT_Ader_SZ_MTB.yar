
rule Trojan_BAT_Ader_SZ_MTB{
	meta:
		description = "Trojan:BAT/Ader.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 08 6f 34 00 00 0a 0d 09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 60 d1 9d 00 08 17 58 0c 08 07 8e 69 fe 04 13 07 11 07 2d cb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}