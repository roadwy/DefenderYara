
rule Trojan_BAT_FormBook_ABFY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABFY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 6f ?? ?? ?? 0a 00 08 09 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 06 00 11 06 02 16 02 8e 69 6f ?? ?? ?? 0a 00 11 06 6f ?? ?? ?? 0a 00 00 de 0d 11 06 2c 08 11 06 6f ?? ?? ?? 0a 00 dc 08 6f ?? ?? ?? 0a 0a 00 de 0b } //2
		$a_01_1 = {67 00 6f 00 64 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 god.Properties.Resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}