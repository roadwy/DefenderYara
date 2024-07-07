
rule Trojan_BAT_NjRAT_PSWB_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PSWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 17 28 90 01 01 00 00 06 3a 52 00 00 00 26 20 02 00 00 00 38 2d 00 00 00 08 14 72 e3 00 00 70 16 8d 14 00 00 01 14 14 14 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}