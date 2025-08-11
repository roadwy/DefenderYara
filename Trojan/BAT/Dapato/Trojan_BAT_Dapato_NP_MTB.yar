
rule Trojan_BAT_Dapato_NP_MTB{
	meta:
		description = "Trojan:BAT/Dapato.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 28 07 00 00 06 00 00 72 13 00 00 70 28 23 00 00 0a 8e 69 17 fe 02 0c 08 2c 14 00 72 13 00 00 70 28 23 00 00 0a 16 9a } //3
		$a_01_1 = {4b 6e 6f 63 6b 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Knocker.Properties.Resources
		$a_01_2 = {6b 6e 6b 73 76 63 2e 65 78 65 } //1 knksvc.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}