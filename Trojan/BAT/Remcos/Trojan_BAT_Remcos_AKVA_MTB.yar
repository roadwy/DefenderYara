
rule Trojan_BAT_Remcos_AKVA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AKVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 2d 19 2b 1c 2b 1d 1d 2d 21 26 72 ?? ?? 01 70 2b 1c 2b 21 2b 22 2b 27 2b 28 2b 2d 17 2c ec de 36 02 2b e1 28 ?? 00 00 06 2b dc 0a 2b dd 28 ?? 00 00 0a 2b dd 06 2b dc 28 ?? 00 00 06 2b d7 06 2b d6 28 ?? 00 00 06 2b d1 0b 2b d0 } //5
		$a_01_1 = {08 02 59 07 59 20 ff 00 00 00 25 2c f7 5f 16 2d 15 d2 0c 08 66 16 2d ed d2 0c 06 07 08 9c 07 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}