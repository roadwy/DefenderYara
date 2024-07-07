
rule Trojan_Win32_Ekstak_ASEQ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {51 c7 44 24 00 00 00 00 00 ff 15 90 02 03 00 85 c0 74 0c 8d 4c 24 00 51 50 ff 15 90 02 03 00 8b 44 24 00 59 c3 90 00 } //5
		$a_03_1 = {57 ff d3 68 90 02 03 00 57 89 86 90 01 02 00 00 ff d3 68 90 02 03 00 57 89 86 90 01 02 00 00 ff d3 8d 54 24 0c 89 86 90 01 02 00 00 52 c7 44 24 10 14 01 00 00 ff 15 90 00 } //5
		$a_03_2 = {8b 54 24 04 52 ff 15 90 02 03 00 8b 44 24 0c 8b 7c 24 10 0b c7 5f 83 f0 11 f7 d8 1b c0 40 83 c4 14 c3 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=5
 
}