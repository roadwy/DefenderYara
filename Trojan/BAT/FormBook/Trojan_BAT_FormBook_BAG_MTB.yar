
rule Trojan_BAT_FormBook_BAG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 75 00 00 70 0a 06 28 45 00 00 0a 25 26 0b 28 46 00 00 0a 07 16 07 8e 69 ?? ?? 00 00 0a 25 26 0a 28 37 00 00 0a 06 ?? ?? 00 00 0a 25 26 0c 1f 61 6a 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}