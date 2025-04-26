
rule Trojan_BAT_Tiny_AC_MTB{
	meta:
		description = "Trojan:BAT/Tiny.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 11 00 07 00 00 "
		
	strings :
		$a_02_0 = {0a 18 5b 8d 03 ?? ?? 01 0a 16 0b 38 ?? ?? ?? 00 06 07 18 5b 02 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 07 18 58 0b 07 02 } //10
		$a_80_1 = {7a 69 72 69 6b 61 74 75 } //zirikatu  4
		$a_80_2 = {62 75 72 75 74 75 } //burutu  4
		$a_80_3 = {48 65 78 53 74 72 69 6e 67 54 6f 42 79 74 65 41 72 72 61 79 } //HexStringToByteArray  3
		$a_80_4 = {47 65 74 43 6f 6e 73 6f 6c 65 57 69 6e 64 6f 77 } //GetConsoleWindow  2
		$a_80_5 = {72 65 74 31 41 72 67 44 65 6c 65 67 61 74 65 } //ret1ArgDelegate  2
		$a_80_6 = {7b 30 3a 78 7d } //{0:x}  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*4+(#a_80_2  & 1)*4+(#a_80_3  & 1)*3+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2) >=17
 
}