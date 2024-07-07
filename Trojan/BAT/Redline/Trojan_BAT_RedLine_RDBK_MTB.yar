
rule Trojan_BAT_RedLine_RDBK_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {36 66 63 37 30 61 62 61 2d 31 32 66 31 2d 34 66 38 32 2d 39 32 32 36 2d 62 63 33 34 35 31 36 30 36 62 31 33 } //1 6fc70aba-12f1-4f82-9226-bc3451606b13
		$a_01_1 = {42 00 6c 00 61 00 63 00 6b 00 48 00 61 00 74 00 54 00 6f 00 6f 00 6c 00 7a 00 2e 00 63 00 6f 00 6d 00 20 00 32 00 30 00 31 00 39 00 } //1 BlackHatToolz.com 2019
		$a_01_2 = {50 00 69 00 6e 00 74 00 65 00 72 00 65 00 73 00 74 00 20 00 42 00 6f 00 61 00 72 00 64 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //1 Pinterest Board Manager
		$a_01_3 = {72 63 4b 45 47 } //1 rcKEG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}