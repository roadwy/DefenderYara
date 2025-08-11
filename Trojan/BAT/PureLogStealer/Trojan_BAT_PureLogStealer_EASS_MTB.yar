
rule Trojan_BAT_PureLogStealer_EASS_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.EASS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8f 0c 00 00 01 25 71 0c 00 00 01 11 07 11 08 11 07 8e 69 5d 91 61 d2 81 0c 00 00 01 11 08 17 58 13 08 11 08 11 06 8e } //1
		$a_02_1 = {11 09 11 0a 16 20 00 10 00 00 ?? ?? ?? ?? ?? 13 0c 11 0c 16 31 0c 11 0b 11 0a 16 11 0c ?? ?? ?? ?? ?? 11 0c 16 30 d9 } //1
		$a_01_2 = {68 00 6b 00 67 00 75 00 54 00 7a 00 53 00 43 00 62 00 37 00 35 00 67 00 37 00 73 00 4a 00 39 00 43 00 68 00 4d 00 63 00 6d 00 41 00 4f 00 50 00 70 00 65 00 42 00 4c 00 39 00 5a 00 4a 00 79 00 2f 00 74 00 65 00 6a 00 6e 00 6f 00 43 00 6a 00 54 00 2b 00 45 00 3d 00 } //1 hkguTzSCb75g7sJ9ChMcmAOPpeBL9ZJy/tejnoCjT+E=
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}