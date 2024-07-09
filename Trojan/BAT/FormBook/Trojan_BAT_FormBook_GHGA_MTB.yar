
rule Trojan_BAT_FormBook_GHGA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.GHGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 7f 02 00 70 6f ?? ?? ?? 0a 74 01 00 00 1b 0a 73 42 00 00 0a 0b 73 43 00 00 0a 0c 14 0d 1e 8d 42 00 00 01 13 04 08 1b 8d 42 00 00 01 25 d0 b2 00 00 04 } //2
		$a_01_1 = {4b 00 75 00 6c 00 69 00 62 00 69 00 6e 00 67 00 } //1 Kulibing
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}