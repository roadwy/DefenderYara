
rule TrojanSpy_Win32_Ranbyus_N{
	meta:
		description = "TrojanSpy:Win32/Ranbyus.N,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 55 0c 0f b6 14 17 c1 e1 08 0b ca 47 3b 7d 10 75 02 33 ff 4b 75 e9 31 08 83 c0 04 ff 4d 08 75 } //2
		$a_01_1 = {6e 65 77 69 6d 61 78 69 6e 74 65 72 6e 65 74 78 78 78 2e 63 6f 6d 2f 77 61 76 } //1 newimaxinternetxxx.com/wav
		$a_01_2 = {76 26 78 45 69 52 34 33 23 24 00 } //1
		$a_01_3 = {73 79 73 74 65 6d 20 63 68 65 63 6b 2e 6c 6e 6b 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}