
rule Trojan_BAT_SnakeStealer_NA_MTB{
	meta:
		description = "Trojan:BAT/SnakeStealer.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 09 58 04 09 91 52 09 17 58 0d 09 04 8e 69 32 ef } //5
		$a_01_1 = {06 11 06 11 08 58 91 07 11 08 91 2e 05 16 13 07 2b 0d 11 08 17 58 13 08 11 08 07 8e 69 32 e1 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}