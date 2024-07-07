
rule TrojanSpy_Win32_Setfic_A{
	meta:
		description = "TrojanSpy:Win32/Setfic.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {fc 51 ad 03 c5 50 ff b5 90 01 04 8b 85 90 01 04 ff d0 ab 59 e2 e9 8d 85 90 01 04 50 68 01 01 00 00 90 00 } //2
		$a_01_1 = {74 07 3d 48 45 41 44 75 37 2b d2 ac 42 3c 20 } //1
		$a_03_2 = {81 3e 55 53 45 52 75 6e 83 f8 6e 74 69 a1 90 01 04 50 c1 e0 02 90 00 } //1
		$a_01_3 = {50 72 78 52 75 6e 53 65 72 76 69 63 65 00 } //1 牐剸湵敓癲捩e
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}