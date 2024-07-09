
rule Trojan_BAT_FormBook_ESE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ESE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 03 11 06 02 11 06 91 11 02 18 d6 18 da 61 11 01 11 07 19 d6 19 da 91 61 b4 } //1
		$a_03_1 = {11 01 02 11 03 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}