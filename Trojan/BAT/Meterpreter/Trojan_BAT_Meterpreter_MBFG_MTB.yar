
rule Trojan_BAT_Meterpreter_MBFG_MTB{
	meta:
		description = "Trojan:BAT/Meterpreter.MBFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 15 11 15 11 0e 11 12 7e ?? 00 00 0a 6f ?? 00 00 06 26 72 ?? ?? ?? 70 17 8d ?? 00 00 01 25 16 12 09 7c ?? 00 00 04 72 ?? 02 00 70 28 ?? 00 00 0a a2 13 1b 11 1b } //1
		$a_01_1 = {68 00 61 00 63 00 6b 00 65 00 64 00 61 00 6e 00 79 00 77 00 61 00 79 00 } //1 hackedanyway
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}