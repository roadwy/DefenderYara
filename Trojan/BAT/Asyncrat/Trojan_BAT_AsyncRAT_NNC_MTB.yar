
rule Trojan_BAT_AsyncRAT_NNC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 28 12 00 00 0a 25 26 0b 28 ?? 00 00 0a 25 26 07 16 07 8e 69 6f 28 00 00 0a } //5
		$a_01_1 = {4c 69 6d 65 5f 41 73 79 6e 63 43 6c 69 65 6e 74 } //1 Lime_AsyncClient
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}