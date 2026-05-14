
rule Trojan_BAT_ClipBanker_SX_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 05 00 00 0a 2c 37 28 06 00 00 0a 0a 06 7e 03 00 00 04 28 07 00 00 0a 2c 24 06 28 08 00 00 0a 2d 1c 06 80 03 00 00 04 06 28 03 00 00 06 0b 07 28 09 00 00 0a 2d 07 07 06 28 05 00 00 06 de 03 } //30
		$a_01_1 = {02 17 8d 0b 00 00 01 0d 09 16 1f 20 9d 09 17 6f 0f 00 00 0a 0a 06 13 04 16 13 05 2b 1d 11 04 11 05 9a 0b 07 72 97 05 00 70 28 0c 00 00 0a 2d 04 16 0c de 10 11 05 17 58 13 05 11 05 11 04 8e 69 32 db 17 2a 08 2a } //20
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}