
rule Trojan_BAT_SilentCryptoMiner_NR_MTB{
	meta:
		description = "Trojan:BAT/SilentCryptoMiner.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 28 58 00 00 0a 28 59 00 00 0a 13 00 20 01 00 00 00 7e 17 02 00 04 7b 2c 02 00 04 3a c9 ff ff ff 26 20 00 00 00 00 38 be ff ff ff 2a } //3
		$a_01_1 = {13 01 20 0b 00 00 00 38 d5 fe ff ff 28 54 00 00 0a 03 6f 55 00 00 0a 13 03 20 0c 00 00 00 38 be fe ff ff } //2
		$a_01_2 = {52 65 6f 78 67 67 79 7a 68 75 78 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Reoxggyzhux.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}