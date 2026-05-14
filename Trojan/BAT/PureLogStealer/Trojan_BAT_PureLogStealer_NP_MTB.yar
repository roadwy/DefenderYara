
rule Trojan_BAT_PureLogStealer_NP_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f fe 0e 31 00 fe 0c 30 00 1a 64 fe 0c 31 00 1a 62 60 fe 0c 28 00 61 fe 0e 30 00 fe 0c 29 00 1d 62 fe 0c 29 00 1f 19 64 60 fe 0e 29 00 fe 0c 2a 00 76 6c } //2
		$a_01_1 = {fe 0c 2a 00 76 6c 5b fe 0c 2a 00 76 6c 58 6d fe 0e 32 00 20 37 ff ff ff 6a fe 0c 28 00 6e 59 6d fe 0c 32 00 58 6e 20 37 ff ff ff 6a 58 6d fe 0e 2a 00 } //1
		$a_01_2 = {53 65 74 70 74 32 36 26 } //1 Setpt26&
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_PureLogStealer_NP_MTB_2{
	meta:
		description = "Trojan:BAT/PureLogStealer.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {7e 2f 00 00 04 07 9a 06 28 79 00 00 0a 39 0b 00 00 00 7e 30 00 00 04 74 1d 00 00 01 2a 07 17 58 0b 07 7e 2f 00 00 04 8e 69 3f d2 ff ff ff } //3
		$a_01_1 = {24 39 35 64 35 65 65 64 38 2d 33 38 30 38 2d 34 32 31 65 2d 39 62 31 31 2d 36 32 64 35 34 66 30 64 65 32 36 35 } //1 $95d5eed8-3808-421e-9b11-62d54f0de265
		$a_01_2 = {4a 00 61 00 76 00 61 00 53 00 63 00 72 00 69 00 70 00 74 00 2d 00 70 00 6c 00 75 00 67 00 69 00 6e 00 2e 00 65 00 78 00 65 00 } //1 JavaScript-plugin.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}