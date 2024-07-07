
rule Trojan_BAT_RedLine_PTFB_MTB{
	meta:
		description = "Trojan:BAT/RedLine.PTFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 ff c1 04 70 28 90 01 01 3f 00 06 28 90 01 01 2b 00 06 0d 09 28 90 01 01 00 00 0a 72 3b c2 04 70 6f 33 00 00 0a 13 04 07 72 5b c2 04 70 6f 34 00 00 0a 0c 11 04 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}