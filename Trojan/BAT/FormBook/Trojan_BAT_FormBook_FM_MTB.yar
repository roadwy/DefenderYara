
rule Trojan_BAT_FormBook_FM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.FM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 17 58 13 04 11 04 06 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}