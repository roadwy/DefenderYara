
rule Trojan_BAT_FormBook_NZJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 06 07 11 06 91 11 04 11 11 95 61 ?? ?? 00 00 0a 9c 11 06 17 58 13 06 00 11 06 6e 09 8e 69 } //2
		$a_01_1 = {11 04 11 09 95 11 04 11 07 95 58 20 ff 00 00 00 5f 13 11 11 06 19 5e } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}