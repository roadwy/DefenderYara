
rule Trojan_Win32_PonyStealer_SK_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.SK!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 70 80 11 00 00 04 72 07 00 00 70 80 12 00 00 04 2a } //2
		$a_01_1 = {0f 00 28 1e 00 00 06 0f 01 28 1e 00 00 06 fe 01 16 fe 01 2a } //2
		$a_01_2 = {2b 01 08 0c 00 20 ef 00 00 00 20 ee 00 00 00 28 01 00 00 2b 16 9a 14 16 8d 03 00 00 01 6f 1d 00 00 0a 26 17 13 07 38 b4 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}