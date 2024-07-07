
rule Trojan_BAT_Androm_ADG_MTB{
	meta:
		description = "Trojan:BAT/Androm.ADG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 04 00 00 "
		
	strings :
		$a_02_0 = {02 07 6f 06 00 00 0a 07 03 6f 90 01 03 0a 5d 0c 03 08 6f 06 00 00 0a 0d 09 61 d1 13 04 06 11 04 6f 90 01 03 0a 26 07 17 58 0b 07 02 6f 90 01 03 0a 32 90 00 } //10
		$a_80_1 = {5f 44 52 40 4d 4c 57 } //_DR@MLW  3
		$a_80_2 = {7e 51 43 73 40 4d 51 44 } //~QCs@MQD  3
		$a_80_3 = {44 65 63 72 79 70 74 } //Decrypt  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*2) >=18
 
}