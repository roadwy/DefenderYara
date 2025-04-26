
rule Trojan_BAT_LokiBot_Z_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 02 16 03 8e 69 6f ?? ?? 00 0a 0d 09 13 04 } //2
		$a_03_1 = {0a 0b 07 28 ?? ?? 00 0a 04 6f ?? ?? 00 0a 6f ?? ?? 00 0a 0c 06 08 6f ?? ?? 00 0a 00 06 18 6f } //2
		$a_03_2 = {0c 03 08 73 ?? ?? 00 0a 0d 06 09 06 6f ?? ?? 00 0a 8e 69 6f } //2
		$a_01_3 = {0a 0b 11 04 07 16 07 8e 69 6f } //2
		$a_03_4 = {06 09 06 6f ?? ?? 00 0a 8e 69 6f } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2+(#a_03_4  & 1)*2) >=10
 
}