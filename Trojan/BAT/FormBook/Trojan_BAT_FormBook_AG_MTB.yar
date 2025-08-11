
rule Trojan_BAT_FormBook_AG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 25 16 11 0a 75 0b 00 00 1b 16 99 d2 9c 25 17 11 0a 74 0b 00 00 1b 17 99 d2 9c 25 18 11 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}