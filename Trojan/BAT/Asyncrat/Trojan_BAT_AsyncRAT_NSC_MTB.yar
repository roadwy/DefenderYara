
rule Trojan_BAT_AsyncRAT_NSC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 0a 1f 1c 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 00 00 08 06 07 6f ?? 00 00 0a 00 07 28 ?? 00 00 06 } //5
		$a_01_1 = {6b 75 72 64 69 73 68 62 75 69 6c 64 } //1 kurdishbuild
		$a_01_2 = {68 78 63 61 2e 65 78 65 } //1 hxca.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_BAT_AsyncRAT_NSC_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRAT.NSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 88 00 00 0a 7e ?? 00 00 04 07 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0d 28 ?? 00 00 0a 09 16 09 8e 69 6f ?? 00 00 0a 28 ?? 00 00 0a 13 04 7e ?? 00 00 04 2c 08 02 11 04 28 ?? 00 00 06 11 04 13 05 de 06 } //5
		$a_01_1 = {4e 61 73 68 77 69 6c 6c 65 } //1 Nashwille
		$a_01_2 = {4e 65 74 2e 65 78 65 } //1 Net.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}