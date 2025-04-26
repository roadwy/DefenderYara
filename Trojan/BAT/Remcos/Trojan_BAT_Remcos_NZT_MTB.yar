
rule Trojan_BAT_Remcos_NZT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 06 13 06 08 09 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 07 11 07 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a de } //1
		$a_01_1 = {57 00 77 00 69 00 68 00 6c 00 61 00 61 00 7a 00 73 00 68 00 6a 00 63 00 78 00 6c 00 61 00 72 00 69 00 2e 00 58 00 68 00 62 00 76 00 69 00 75 00 73 00 73 00 61 00 6d 00 6f 00 6c 00 63 00 7a 00 62 00 6f 00 62 00 79 00 } //3 Wwihlaazshjcxlari.Xhbviussamolczboby
		$a_01_2 = {41 00 6d 00 78 00 65 00 77 00 6f 00 65 00 77 00 69 00 6f 00 74 00 64 00 73 00 72 00 6f 00 78 00 65 00 6d 00 69 00 6b 00 63 00 78 00 64 00 6f 00 2e 00 52 00 7a 00 6f 00 70 00 67 00 6c 00 79 00 6e 00 } //3 Amxewoewiotdsroxemikcxdo.Rzopglyn
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=4
 
}