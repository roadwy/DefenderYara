
rule Trojan_BAT_NjRAT_PTDN_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PTDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 03 00 00 2b 07 28 ?? 00 00 06 80 06 00 00 04 07 8e 69 8d 1a 00 00 01 13 04 17 13 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}