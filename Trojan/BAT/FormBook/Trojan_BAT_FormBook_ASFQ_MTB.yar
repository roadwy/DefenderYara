
rule Trojan_BAT_FormBook_ASFQ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ASFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 20 00 02 00 00 58 20 00 01 00 00 5d 20 00 04 00 00 58 20 00 02 00 00 5d 20 00 01 00 00 59 20 00 04 00 00 58 20 ff 00 00 00 5f } //5
		$a_03_1 = {20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 08 a2 28 } //2
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}