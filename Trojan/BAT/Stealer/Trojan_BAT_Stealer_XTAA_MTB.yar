
rule Trojan_BAT_Stealer_XTAA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.XTAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 0c 00 fe 0c 0b 00 fe 0c 0c 00 fe 0c 0b 00 91 fe 0c 11 00 fe 0c 0b 00 fe 0c 11 00 8e 69 5d 91 61 d2 9c fe 0c 0b 00 20 ea f1 00 00 20 eb f1 00 00 61 58 fe 0e 0b 00 } //3
		$a_01_1 = {20 1d 53 ff ff 20 e4 ac 00 00 58 8d 10 00 00 01 fe 0e 00 00 fe 0c 00 00 20 00 00 00 00 20 0f 71 d7 13 20 17 da 00 00 61 20 22 38 ff ff 20 fd c7 00 00 58 5f 62 20 aa 58 ff ff 20 56 a7 00 00 58 20 bf 36 ff ff 20 61 c9 00 00 58 20 70 1b d7 13 20 68 b0 00 00 61 59 20 1f 00 00 00 5f 64 60 fe 09 00 00 a2 fe 0c 00 00 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}