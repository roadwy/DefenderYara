
rule Trojan_BAT_FormBook_AHDN_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AHDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 07 06 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07 } //2
		$a_01_1 = {52 00 75 00 6e 00 6f 00 } //1 Runo
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}