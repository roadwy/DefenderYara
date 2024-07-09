
rule TrojanDropper_Win32_Popsenong_A{
	meta:
		description = "TrojanDropper:Win32/Popsenong.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 00 3a 00 5c 00 73 00 68 00 65 00 6e 00 6c 00 6f 00 6e 00 67 00 5c 00 27 59 a2 5b 37 62 5c 00 [0-20] 56 00 42 00 ea 81 2f 54 a8 52 5c 00 ca 91 3e 65 ef 7a 5c 00 e5 5d 0b 7a 31 00 2e 00 76 00 62 00 70 } //1
		$a_01_1 = {4d 6f 64 44 65 6c 65 74 65 4d 65 00 } //1 潍䑤汥瑥䵥e
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}