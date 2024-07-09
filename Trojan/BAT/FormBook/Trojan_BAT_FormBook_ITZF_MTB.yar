
rule Trojan_BAT_FormBook_ITZF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ITZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 6f ?? ?? ?? 0a 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 07 06 11 07 } //2
		$a_01_1 = {41 00 65 00 65 00 65 00 65 00 } //1 Aeeee
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}