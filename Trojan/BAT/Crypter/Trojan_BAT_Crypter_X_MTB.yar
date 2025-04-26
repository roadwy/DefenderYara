
rule Trojan_BAT_Crypter_X_MTB{
	meta:
		description = "Trojan:BAT/Crypter.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 00 00 11 00 28 ?? 00 00 0a 7e 03 00 00 04 28 18 00 00 06 74 01 00 00 1b 0a 28 17 00 00 06 26 28 16 00 00 06 16 fe 01 0d 09 2d 02 16 0b 16 0b 2b ?? 00 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 06 07 00 } //5
		$a_00_1 = {58 65 67 65 72 } //2 Xeger
		$a_00_2 = {46 61 72 65 } //2 Fare
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=9
 
}