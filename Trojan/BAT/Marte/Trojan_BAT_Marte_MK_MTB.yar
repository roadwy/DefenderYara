
rule Trojan_BAT_Marte_MK_MTB{
	meta:
		description = "Trojan:BAT/Marte.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 19 63 0a 1d 5f 2c 04 06 17 58 0a 06 8d 8d 00 00 01 0b 06 19 5f 0c 08 2d 02 1a 0c 16 0d 02 7b 01 00 00 04 } //25
		$a_01_1 = {06 17 59 8f 8b 00 00 01 25 4b 09 60 54 15 1f 20 07 59 1f 1f 5f 64 0d 02 7b 02 00 00 04 } //10
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*10) >=35
 
}