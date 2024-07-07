
rule Trojan_BAT_Stealer_SO_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {14 0a 73 01 00 00 0a 72 01 00 00 70 28 02 00 00 0a 0a 02 7b 01 00 00 04 06 7d 02 00 00 04 dd 06 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}