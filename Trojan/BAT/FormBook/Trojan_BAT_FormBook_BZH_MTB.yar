
rule Trojan_BAT_FormBook_BZH_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BZH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 14 0c 1e 8d 90 01 03 01 0d 28 90 01 03 06 13 04 11 04 16 09 16 1e 28 90 01 03 0a 90 00 } //2
		$a_01_1 = {4b 00 75 00 6c 00 69 00 62 00 69 00 6e 00 67 00 } //1 Kulibing
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}