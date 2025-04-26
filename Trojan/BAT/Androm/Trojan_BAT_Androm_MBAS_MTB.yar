
rule Trojan_BAT_Androm_MBAS_MTB{
	meta:
		description = "Trojan:BAT/Androm.MBAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 0d 07 03 6f ?? 00 00 0a 5d 13 04 03 11 04 6f ?? 00 00 0a 13 05 11 05 13 06 09 11 06 61 13 07 11 07 d1 13 08 06 11 08 6f ?? 00 00 0a 26 00 07 17 58 0b 07 02 6f ?? 00 00 0a fe 04 13 0a 11 0a 2d b5 } //1
		$a_01_1 = {73 4f 6d 4e 75 53 6f 52 } //1 sOmNuSoR
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}