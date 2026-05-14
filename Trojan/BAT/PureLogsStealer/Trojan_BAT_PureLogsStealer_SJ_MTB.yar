
rule Trojan_BAT_PureLogsStealer_SJ_MTB{
	meta:
		description = "Trojan:BAT/PureLogsStealer.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {11 04 16 28 0f 00 00 0a 13 05 38 00 00 00 00 11 0b 16 73 10 00 00 0a 13 06 20 06 00 00 00 7e 3e 00 00 04 7b 65 00 00 04 39 b3 ff ff ff 26 20 01 00 00 00 38 a8 ff ff ff 11 0b 11 04 16 1a 6f 11 00 00 0a 26 38 b7 ff ff ff } //1
		$a_81_1 = {47 73 76 67 69 79 61 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Gsvgiya.Properties.Resources
		$a_81_2 = {24 34 61 64 39 36 30 32 31 2d 30 30 61 35 2d 34 39 35 62 2d 61 38 31 66 2d 31 37 65 62 63 38 37 33 30 33 34 32 } //1 $4ad96021-00a5-495b-a81f-17ebc8730342
		$a_81_3 = {73 65 52 39 63 75 58 79 4b } //1 seR9cuXyK
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}