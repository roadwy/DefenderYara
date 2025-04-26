
rule Trojan_BAT_RemcosRAT_SZJF_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.SZJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 18 5d 2c 0a 02 06 07 6f ?? 00 00 0a 2b 08 02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d } //5
		$a_03_1 = {26 00 03 19 8d ?? 00 00 01 25 16 11 07 16 91 9c 25 17 11 07 17 91 9c 25 18 11 07 18 91 9c } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}