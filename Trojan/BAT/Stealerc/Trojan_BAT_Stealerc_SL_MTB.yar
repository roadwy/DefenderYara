
rule Trojan_BAT_Stealerc_SL_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 06 07 6f 5c 00 00 0a 0c 04 03 6f 5d 00 00 0a 59 0d 09 19 32 2c 03 19 8d 58 00 00 01 25 16 12 02 28 5e 00 00 0a 9c 25 17 12 02 28 5f 00 00 0a 9c 25 18 12 02 28 60 00 00 0a 9c } //2
		$a_81_1 = {50 6f 6b 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 Poker.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}