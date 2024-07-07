
rule Trojan_BAT_Formbook_MBID_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MBID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 04 02 11 04 91 07 61 06 09 91 61 28 90 01 01 00 00 0a 9c 09 06 8e 69 17 59 fe 01 13 05 11 05 2c 04 90 00 } //1
		$a_01_1 = {58 00 00 05 58 00 31 00 00 05 58 00 32 00 00 0f 4d 00 6f 00 64 00 75 00 6c 00 65 00 31 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}