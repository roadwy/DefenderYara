
rule Trojan_BAT_NjRAT_PTEJ_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PTEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 1c 00 00 0a 28 90 01 01 00 00 0a 0a 28 90 01 01 00 00 0a 06 6f 1f 00 00 0a 6f 20 00 00 0a 14 14 6f 21 00 00 0a 26 00 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}