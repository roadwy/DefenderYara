
rule Trojan_BAT_FormBook_AJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 06 8e 69 6a 5d 69 06 08 06 8e 69 6a 5d 69 91 02 08 02 8e 69 6a 5d 69 91 61 06 08 17 6a 58 06 8e 69 6a 5d 69 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}