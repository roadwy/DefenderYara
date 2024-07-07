
rule TrojanProxy_Win32_Wermud_A{
	meta:
		description = "TrojanProxy:Win32/Wermud.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {81 c6 20 03 00 00 81 e9 20 03 00 00 81 fe 00 00 00 05 } //1
		$a_01_1 = {be 00 00 30 00 57 c7 44 24 10 00 00 00 00 89 74 24 1c 8d 44 24 10 8d 4c 24 28 50 68 00 04 00 00 } //1
		$a_01_2 = {6a 04 68 00 10 00 00 68 a4 01 00 00 6a 00 56 ff d7 8b d8 85 db 75 0b } //1
		$a_01_3 = {b1 74 b3 70 b2 3a 50 57 c7 45 00 00 00 00 00 33 f6 c6 44 24 20 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}