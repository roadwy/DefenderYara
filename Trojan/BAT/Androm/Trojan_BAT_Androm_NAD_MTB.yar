
rule Trojan_BAT_Androm_NAD_MTB{
	meta:
		description = "Trojan:BAT/Androm.NAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {2b 2f 1e 2c 1d 20 ef be 66 06 25 2c 0a 61 2b 24 2b 26 7e 81 00 00 04 16 2d f0 59 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {52 43 32 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 RC2CryptoServiceProvider
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_Androm_NAD_MTB_2{
	meta:
		description = "Trojan:BAT/Androm.NAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 10 6f 82 00 00 06 20 ?? ?? ?? 00 38 ?? ?? ?? ff 11 07 16 8c ?? ?? ?? 01 7e ?? ?? ?? 04 13 10 11 10 6f ?? ?? ?? 0a 26 38 ?? ?? ?? ff 02 7b ?? ?? ?? 04 16 28 ?? ?? ?? 06 20 ?? ?? ?? 00 38 ?? ?? ?? ff } //5
		$a_01_1 = {47 4e 4f 4c 43 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 GNOLC.g.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}