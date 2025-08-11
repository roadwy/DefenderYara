
rule Trojan_BAT_FormBook_EGFB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EGFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 03 11 21 11 22 91 ?? ?? ?? ?? ?? 00 72 f1 01 00 70 12 22 ?? ?? 00 00 0a ?? ?? 00 00 0a 13 05 00 11 22 17 58 13 22 11 22 11 1a fe 04 13 23 11 23 2d cd } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}