
rule Trojan_BAT_FormBook_EVA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 02 08 1f 32 da 1f 32 d6 18 ?? ?? ?? ?? ?? 1f 10 ?? ?? ?? ?? ?? 84 } //1
		$a_01_1 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}