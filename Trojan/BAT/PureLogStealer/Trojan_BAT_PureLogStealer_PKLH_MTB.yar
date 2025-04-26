
rule Trojan_BAT_PureLogStealer_PKLH_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.PKLH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {0b 14 0c 2b [0-14] 08 16 08 8e 69 6f ?? 00 00 0a 0d de 0a 06 2c 06 06 6f ?? 00 00 0a dc } //8
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=10
 
}