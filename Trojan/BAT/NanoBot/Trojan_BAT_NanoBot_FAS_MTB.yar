
rule Trojan_BAT_NanoBot_FAS_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.FAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 09 02 8e 69 5d 02 09 02 8e 69 5d 91 07 09 07 8e 69 5d 91 61 02 09 17 d6 02 8e 69 5d 91 da 72 } //2
		$a_01_1 = {0a 5d b4 9c 09 15 d6 0d 09 16 2f c1 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}