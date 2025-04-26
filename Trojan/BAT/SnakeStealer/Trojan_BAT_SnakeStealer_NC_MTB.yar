
rule Trojan_BAT_SnakeStealer_NC_MTB{
	meta:
		description = "Trojan:BAT/SnakeStealer.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 8e 69 5d 09 8e 69 58 09 8e 69 5d 91 } //3
		$a_01_1 = {07 11 08 08 5d 08 58 08 5d 91 13 09 16 13 18 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}