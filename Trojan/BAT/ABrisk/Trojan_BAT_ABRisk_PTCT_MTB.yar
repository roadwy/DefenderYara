
rule Trojan_BAT_ABRisk_PTCT_MTB{
	meta:
		description = "Trojan:BAT/ABRisk.PTCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 6f 00 00 0a 00 02 72 fd 02 00 70 72 0d 03 00 70 6f 31 00 00 06 26 20 10 27 00 00 28 90 01 01 00 00 0a 00 02 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}