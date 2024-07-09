
rule Trojan_BAT_FormBook_WNVF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.WNVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {18 17 8d 19 00 00 01 25 16 06 a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 26 06 28 ?? ?? ?? 0a 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}