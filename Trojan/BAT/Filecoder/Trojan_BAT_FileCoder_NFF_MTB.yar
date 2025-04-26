
rule Trojan_BAT_FileCoder_NFF_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.NFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 1a 00 00 0a 03 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 04 6f ?? 00 00 0a 0b 28 ?? 00 00 0a 07 6f ?? 00 00 0a 0b 02 06 07 28 ?? 00 00 06 28 ?? 00 00 0a } //5
		$a_01_1 = {50 61 79 4f 72 44 69 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 PayOrDie.Properties.Resources.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}