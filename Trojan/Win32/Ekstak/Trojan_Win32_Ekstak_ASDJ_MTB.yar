
rule Trojan_Win32_Ekstak_ASDJ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 4c 24 10 51 ff d3 56 8b f8 ff 15 [0-03] 00 50 56 57 ff 15 [0-03] 00 85 c0 74 } //1
		$a_01_1 = {5e 33 c0 5b 81 c4 14 04 00 00 c3 5f 5e b8 01 00 00 00 5b 81 c4 14 04 00 00 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}