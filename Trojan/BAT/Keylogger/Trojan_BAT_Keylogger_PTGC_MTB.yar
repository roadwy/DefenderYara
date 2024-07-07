
rule Trojan_BAT_Keylogger_PTGC_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.PTGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e 32 00 00 04 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 2c 0a 11 04 09 6f d2 00 00 0a 2b 6c 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}