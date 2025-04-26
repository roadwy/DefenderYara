
rule Trojan_BAT_FormBook_AUGA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AUGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 25 16 11 0b 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 0b 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 0b 20 ff 00 00 00 5f d2 9c } //3
		$a_03_1 = {01 25 16 12 06 28 ?? 00 00 0a 9c 25 17 12 06 28 ?? 00 00 0a 9c 25 18 12 06 28 ?? 00 00 0a 9c 11 08 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}