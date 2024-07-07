
rule Trojan_BAT_AsyncRat_WFC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.WFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 91 0d 06 72 c6 0a 00 70 09 8c 0b 00 00 01 28 90 01 03 0a 6f 90 01 03 0a 26 08 17 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}