
rule Trojan_BAT_Crysan_NC_MTB{
	meta:
		description = "Trojan:BAT/Crysan.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 79 04 00 06 0a 06 03 7d bf 00 00 04 02 6f 0c 00 00 0a 06 fe 06 7a 04 00 06 73 0d 00 00 0a 28 04 00 00 2b 25 } //3
		$a_01_1 = {28 09 00 00 0a 02 6f 0a 00 00 0a 0a dd 07 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}