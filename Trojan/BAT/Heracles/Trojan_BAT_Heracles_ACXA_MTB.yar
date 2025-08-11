
rule Trojan_BAT_Heracles_ACXA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.ACXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 03 11 00 11 03 91 11 01 11 03 11 01 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 20 } //5
		$a_01_1 = {11 03 17 58 13 03 20 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}