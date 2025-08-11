
rule Trojan_BAT_Stealer_SLGA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SLGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 28 0d 00 00 06 6f 02 00 00 0a 25 16 6f 03 00 00 0a 74 04 00 00 01 13 00 25 11 00 72 01 00 00 70 6f 04 00 00 0a 72 31 00 00 70 6f 05 00 00 0a 6f 02 00 00 0a 25 17 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}