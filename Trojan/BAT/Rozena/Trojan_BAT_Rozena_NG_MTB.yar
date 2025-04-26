
rule Trojan_BAT_Rozena_NG_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {16 0a 7e 13 00 00 0a 0b 72 01 00 00 70 28 05 00 00 06 0c 08 8e 69 28 06 00 00 06 0d 08 09 28 07 00 00 06 00 09 12 00 28 08 00 00 06 0b 07 } //3
		$a_01_1 = {64 6c 6c 6d 65 74 68 6f 64 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 dllmethod.g.resources
		$a_01_2 = {53 68 65 6c 6c 63 6f 64 65 45 78 65 63 75 74 6f 72 } //1 ShellcodeExecutor
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}