
rule Trojan_BAT_AgentTesla_ABA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 1d 09 6f [0-03] 0a 13 07 08 11 07 07 02 11 07 18 5a 18 6f [0-03] 0a 6f [0-03] 0a 9c 09 6f } //2
		$a_01_1 = {45 6c 72 65 64 6b 63 63 6a 72 6e 65 6d 71 71 71 69 64 6f 68 6b } //1 Elredkccjrnemqqqidohk
		$a_01_2 = {47 65 74 42 75 66 66 65 72 } //1 GetBuffer
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_AgentTesla_ABA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 31 00 07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 06 17 58 0a 00 08 17 58 0c 08 20 ?? ?? ?? 00 fe 04 13 05 11 05 2d a9 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 80 ?? ?? ?? 04 2a } //6
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_2 = {47 00 72 00 65 00 79 00 } //1 Grey
		$a_01_3 = {41 00 70 00 70 00 4b 00 61 00 74 00 61 00 43 00 73 00 76 00 56 00 69 00 65 00 77 00 65 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 AppKataCsvViewer.Properties.Resources
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=9
 
}