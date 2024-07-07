
rule Trojan_Win32_Dridex_AX_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {ff ff b8 08 00 00 00 c1 e0 02 89 45 fc 8b 4d fc 81 b9 90 01 04 1e 04 00 00 75 25 8b 55 fc 83 ba 34 c0 12 01 00 75 19 b8 08 00 00 00 d1 e0 8b 0d 90 01 04 03 88 90 00 } //10
		$a_80_1 = {53 65 6c 6c 68 6f 75 72 } //Sellhour  3
		$a_80_2 = {53 75 72 70 72 69 73 65 6d 6f 73 74 } //Surprisemost  3
		$a_80_3 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //GetAsyncKeyState  3
		$a_80_4 = {31 33 37 2d 6c 69 74 74 6c 65 } //137-little  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}