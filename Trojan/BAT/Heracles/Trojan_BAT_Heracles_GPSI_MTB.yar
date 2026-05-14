
rule Trojan_BAT_Heracles_GPSI_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GPSI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 d2 9c 00 07 17 58 0b 07 02 8e 69 } //5
		$a_01_1 = {53 00 4e 00 49 00 50 00 45 00 52 00 5f 00 32 00 30 00 32 00 36 } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}