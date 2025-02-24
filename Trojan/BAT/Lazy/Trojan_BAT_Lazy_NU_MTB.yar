
rule Trojan_BAT_Lazy_NU_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {17 33 1d 73 5c 00 00 0a 25 72 b6 01 00 70 6f 5d 00 00 0a 25 17 6f 5e 00 00 0a 28 5f 00 00 0a 26 02 } //3
		$a_01_1 = {72 b0 04 00 70 02 7b 10 00 00 04 6f 3a 00 00 0a 28 72 00 00 0a 72 ba 04 00 70 6f 73 00 00 0a 72 64 0b 00 70 72 ba 04 00 70 6f 73 00 00 0a 28 6b 00 00 06 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}