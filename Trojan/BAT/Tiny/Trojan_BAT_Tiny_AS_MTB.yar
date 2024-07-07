
rule Trojan_BAT_Tiny_AS_MTB{
	meta:
		description = "Trojan:BAT/Tiny.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 07 00 00 "
		
	strings :
		$a_02_0 = {08 09 16 20 a0 86 01 00 6f 90 01 03 0a 13 07 11 07 2c 19 11 07 15 2e 14 11 05 09 16 11 07 6f 90 01 03 0a 11 04 11 07 58 13 04 2b d4 90 00 } //10
		$a_80_1 = {68 74 74 70 73 3a 2f 2f 73 74 72 61 6b 2e 78 79 7a 2f 6c 6f 67 32 2e 70 68 70 3f 6e 61 6d 65 3d 7b 30 7d 26 72 65 63 3d 7b 31 7d } //https://strak.xyz/log2.php?name={0}&rec={1}  5
		$a_80_2 = {53 65 6e 64 4c 6f 67 4d 65 73 73 61 67 65 } //SendLogMessage  5
		$a_80_3 = {64 65 66 65 6e 64 65 72 75 74 69 6c 69 74 79 } //defenderutility  5
		$a_80_4 = {73 69 6d 70 6c 65 44 6f 77 6e 6c 6f 61 64 65 72 } //simpleDownloader  3
		$a_80_5 = {74 61 73 6b 68 6f 73 74 6d 73 } //taskhostms  3
		$a_80_6 = {74 61 73 6b 68 6f 73 74 6d 73 2e 65 78 65 } //taskhostms.exe  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*5+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=34
 
}