
rule Trojan_BAT_PureCrypter_APR_MTB{
	meta:
		description = "Trojan:BAT/PureCrypter.APR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 07 11 04 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da 06 08 6f ?? 00 00 0a 06 16 6f } //3
		$a_01_1 = {31 00 30 00 33 00 2e 00 32 00 32 00 38 00 2e 00 33 00 37 00 2e 00 35 00 31 00 2f 00 48 00 4f 00 53 00 54 00 31 00 2f 00 56 00 79 00 69 00 67 00 79 00 61 00 66 00 6e 00 2e 00 77 00 61 00 76 00 } //1 103.228.37.51/HOST1/Vyigyafn.wav
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}