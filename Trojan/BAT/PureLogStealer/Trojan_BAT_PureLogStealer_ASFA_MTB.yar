
rule Trojan_BAT_PureLogStealer_ASFA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ASFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 08 28 ?? 02 00 06 17 73 ?? 01 00 0a 13 0c 20 00 00 00 00 7e ?? 02 00 04 39 ?? ff ff ff 26 } //3
		$a_03_1 = {11 0c 02 16 02 8e 69 28 ?? 02 00 06 20 00 00 00 00 7e ?? 02 00 04 3a ?? 00 00 00 26 } //3
		$a_01_2 = {46 34 41 36 38 35 43 41 31 31 31 38 38 32 38 37 39 30 33 36 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //2 F4A685CA111882879036.g.resources
		$a_01_3 = {72 4b 57 4a 54 69 42 75 4b 31 46 53 6b 75 5a 76 44 79 2e 58 4d 37 44 32 33 43 48 75 76 62 6f 6f 71 61 42 72 55 } //2 rKWJTiBuK1FSkuZvDy.XM7D23CHuvbooqaBrU
		$a_01_4 = {59 48 67 38 61 41 4a 78 6f 65 66 74 38 6a 61 37 6e 4d 2e 79 4a 33 69 74 50 4b 66 76 56 4f 6d 4a 6b 6b 6f 63 38 } //2 YHg8aAJxoeft8ja7nM.yJ3itPKfvVOmJkkoc8
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=12
 
}