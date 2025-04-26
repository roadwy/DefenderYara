
rule Trojan_BAT_QuasarRat_NEAH_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.NEAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 18 06 02 07 1e 6f 1f 00 00 0a 18 28 20 00 00 0a 6f 21 00 00 0a 07 1e 58 0b 07 02 6f 22 00 00 0a 32 df } //10
		$a_01_1 = {43 54 5f 56 6f 6f 44 6f 6f } //2 CT_VooDoo
		$a_01_2 = {44 65 63 72 79 70 74 } //2 Decrypt
		$a_01_3 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //2 GetExecutingAssembly
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}