
rule Trojan_WinNT_Otlard_D{
	meta:
		description = "Trojan:WinNT/Otlard.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {47 6f 6f 74 6b 69 74 00 } //1 潇瑯楫t
		$a_01_1 = {8b 08 c1 e9 05 83 e1 07 83 c1 01 83 e1 07 c1 e1 05 } //2
		$a_03_2 = {68 26 c4 31 50 e8 90 01 04 89 85 90 01 04 8b 85 90 01 04 50 68 7f 92 2b 7d e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1) >=3
 
}