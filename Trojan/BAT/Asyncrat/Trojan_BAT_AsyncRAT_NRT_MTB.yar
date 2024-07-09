
rule Trojan_BAT_AsyncRAT_NRT_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 09 00 00 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 0a 72 ?? ?? ?? 70 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 26 2a } //5
		$a_01_1 = {63 72 79 70 74 65 72 32 } //1 crypter2
		$a_01_2 = {72 00 6e 00 61 00 75 00 64 00 61 00 72 00 2a 00 61 00 74 00 32 00 } //1 rnaudar*at2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}