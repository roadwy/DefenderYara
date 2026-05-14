
rule Trojan_BAT_PureLogStealer_RVA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.RVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 0a 11 0a 16 6f ?? 00 00 0a 13 0b 11 0b 13 0c 11 0c 11 04 58 20 ff 00 00 00 5f 13 0c 11 0c 20 aa 00 00 00 61 20 ff 00 00 00 5f 13 0c 11 0c 20 aa 00 00 00 61 20 ff 00 00 00 5f 13 0c 11 0c 11 04 59 20 ff 00 00 00 5f 13 0c 11 0c 66 20 ff 00 00 00 5f 13 0c 11 0c 66 20 ff 00 00 00 5f 13 0c 06 11 0c d2 6f ?? 00 00 0a } //1
		$a_81_1 = {36 36 38 32 37 36 62 62 2d 31 30 37 39 2d 34 32 34 35 2d 39 37 35 32 2d 38 32 34 38 62 37 31 33 61 34 66 34 } //1 668276bb-1079-4245-9752-8248b713a4f4
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}