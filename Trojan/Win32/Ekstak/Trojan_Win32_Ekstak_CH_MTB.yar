
rule Trojan_Win32_Ekstak_CH_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3b d3 58 0f 90 01 05 81 7d e0 4e e6 40 bb 74 90 01 01 8b 15 90 01 04 81 e2 00 00 ff ff 85 d2 75 90 01 01 c7 45 90 01 01 4f e6 40 bb 90 00 } //1
		$a_02_1 = {6a 0a 58 50 ff 75 9c 56 56 ff 15 90 01 04 50 e8 90 01 04 89 45 a0 50 e8 90 01 04 8b 45 ec 8b 08 8b 09 89 4d 98 50 51 e8 90 01 04 59 59 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}