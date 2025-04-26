
rule Trojan_BAT_FormBook_ARHA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ARHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 25 16 11 0c 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 0c 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 0c 20 ff 00 00 00 5f d2 9c } //3
		$a_03_1 = {01 25 16 12 07 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a 9c } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}