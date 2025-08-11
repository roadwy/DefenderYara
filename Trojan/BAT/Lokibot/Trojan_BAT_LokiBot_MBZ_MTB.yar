
rule Trojan_BAT_LokiBot_MBZ_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 00 50 00 53 00 5f 00 47 00 61 00 6d 00 65 } //2
		$a_01_1 = {42 00 61 00 72 00 7a 00 7a 00 65 00 72 00 73 00 } //1 Barzzers
		$a_01_2 = {78 00 78 00 78 00 78 00 78 00 78 00 78 00 00 1b 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 } //1
		$a_01_3 = {50 00 72 00 6f 00 6e 00 48 00 75 00 62 00 } //1 PronHub
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}