
rule Worm_Win32_Gamarue_AN_{
	meta:
		description = "Worm:Win32/Gamarue.AN!!Gamarue.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f be c9 33 c8 c1 c1 09 8b c1 42 8a 0a 84 c9 75 ef } //1
		$a_01_1 = {b8 fc fd fe ff fd ab 2d 04 04 04 04 e2 f8 fc } //1
		$a_01_2 = {ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad } //1
		$a_01_3 = {8b 45 fc c7 84 05 e0 fe ff ff 64 6c 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}