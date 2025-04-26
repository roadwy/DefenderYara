
rule Trojan_BAT_FormBook_DPL_MTB{
	meta:
		description = "Trojan:BAT/FormBook.DPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 91 6f ?? ?? ?? 0a 00 00 08 25 17 59 0c 16 fe 02 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}