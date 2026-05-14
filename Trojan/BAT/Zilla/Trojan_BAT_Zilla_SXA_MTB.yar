
rule Trojan_BAT_Zilla_SXA_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 4e 00 00 06 0a 06 28 ?? 00 00 0a 7d 5e 00 00 04 06 15 7d 5d 00 00 04 06 7c 5e 00 00 04 12 00 28 ?? 00 00 2b 06 7c 5e 00 00 04 } //20
		$a_03_1 = {00 06 2c 1e 06 72 ?? ?? 00 70 6f ?? 00 00 0a 75 3a 00 00 01 0b 07 2c 0a 07 12 02 28 ?? 00 00 0a 2b 01 16 0d 09 2c 05 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}