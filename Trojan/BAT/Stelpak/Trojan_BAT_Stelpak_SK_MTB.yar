
rule Trojan_BAT_Stelpak_SK_MTB{
	meta:
		description = "Trojan:BAT/Stelpak.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 08 28 17 00 00 0a 9c 73 18 00 00 0a 13 04 08 13 05 11 04 11 05 03 8e 69 5d 6f 19 00 00 0a 07 08 03 08 03 8e 69 5d 91 9c 08 17 58 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}