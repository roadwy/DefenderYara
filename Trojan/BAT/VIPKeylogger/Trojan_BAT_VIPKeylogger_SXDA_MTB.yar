
rule Trojan_BAT_VIPKeylogger_SXDA_MTB{
	meta:
		description = "Trojan:BAT/VIPKeylogger.SXDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 37 2b 3c 72 ?? ?? ?? 70 2b 3c 1e 2c 1a 2b 3e 72 ?? ?? ?? 70 2b 3a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 07 6f ?? ?? ?? 0a 06 0c de 37 73 ?? ?? ?? 0a 2b c9 0b 2b c8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}