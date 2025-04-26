
rule Trojan_BAT_FormBook_ANSC_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ANSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 44 2b 45 18 5b 2b 44 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 08 18 25 2c b5 58 0c 1d 2c 04 08 06 32 db } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}