
rule Trojan_BAT_Perseus_DHE_MTB{
	meta:
		description = "Trojan:BAT/Perseus.DHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {11 05 11 04 6f ?? ?? ?? ?? 0d ?? 09 28 ?? ?? ?? ?? ?? da 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? ?? 11 04 17 d6 13 04 11 04 11 06 } //1
		$a_01_1 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //1 EntryPoint
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}