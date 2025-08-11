
rule Trojan_BAT_DCRat_MMK_MTB{
	meta:
		description = "Trojan:BAT/DCRat.MMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 00 00 00 fe 0e 01 00 fe 0c 01 00 20 01 00 00 00 40 00 00 00 00 73 1d 00 00 0a 7e 02 00 00 04 6f ?? 00 00 0a 0a 7e 03 00 00 04 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}