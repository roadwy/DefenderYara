
rule Trojan_BAT_Lazy_NHL_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 16 00 00 0a 0a 72 ?? 00 00 70 0b 72 ?? 00 00 70 0c 06 08 6f ?? 00 00 0a 0d 72 ?? 00 00 70 07 72 ?? 00 00 70 28 ?? 00 00 0a 13 04 72 ?? 00 00 70 13 05 72 ?? 00 00 70 13 06 11 05 28 ?? 00 00 0a 26 06 09 11 04 6f ?? 00 00 0a 00 72 ?? 00 00 70 13 07 00 11 06 28 ?? 00 00 0a 26 11 04 11 07 28 ?? 00 00 0a } //5
		$a_01_1 = {5a 00 65 00 6f 00 6e 00 20 00 56 00 31 00 2e 00 30 00 2e 00 32 00 20 00 42 00 6f 00 6f 00 74 00 73 00 74 00 72 00 61 00 70 00 70 00 65 00 72 00 } //1 Zeon V1.0.2 Bootstrapper
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}