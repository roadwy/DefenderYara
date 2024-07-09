
rule Trojan_BAT_FormBook_NZR_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 02 08 91 03 08 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 00 08 17 58 0c 08 06 fe 04 0d 09 2d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}