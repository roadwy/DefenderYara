
rule Trojan_BAT_Cryptor_B_MTB{
	meta:
		description = "Trojan:BAT/Cryptor.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 02 0a 16 0b 38 f9 00 00 00 06 07 9a 0c 7e 57 00 00 0a 7e 10 00 00 04 08 28 36 00 00 06 73 53 00 00 0a 80 04 00 00 04 7e 12 00 00 04 08 7e 02 00 00 04 7e 11 00 00 04 28 3b 00 00 06 28 40 00 00 06 7e 02 00 00 04 73 50 00 00 0a 80 03 00 00 04 7e 13 00 00 04 7e 03 00 00 04 7e 04 00 00 04 19 20 08 18 02 00 } //1
		$a_00_1 = {66 64 66 72 66 2e 64 6c 6c } //1 fdfrf.dll
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}