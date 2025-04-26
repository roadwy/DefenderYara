
rule Trojan_BAT_AsyncRAT_KAAD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {ee 61 8c 70 9c c1 6d 7f 34 85 4b c8 11 84 00 5a 8d 33 c7 5b c4 0e 03 12 } //4
		$a_01_1 = {a8 b6 08 f9 ba 5e 03 40 3a a9 89 73 34 12 66 4f c8 6a e5 49 b8 5a 4a 4c } //4
		$a_01_2 = {52 43 32 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //3 RC2CryptoServiceProvider
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3) >=11
 
}