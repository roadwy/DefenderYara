
rule Trojan_Win32_Farfli_DAT_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 1e 99 bd 14 4e 01 00 f7 fd 8a 04 39 bd 05 00 00 00 80 ea 77 32 c2 46 88 04 39 8b c1 99 f7 fd 85 d2 75 02 33 f6 8b 44 24 18 41 3b c8 7c } //2
		$a_03_1 = {81 ec c0 09 00 00 b9 70 02 00 00 be 90 01 04 8b fc f3 a5 ff d0 90 00 } //1
		$a_01_2 = {6a 04 68 00 10 00 00 8b 48 10 8b 50 0c 51 8b 4d e4 03 d1 52 ff 15 } //1
		$a_01_3 = {45 e8 89 65 f0 83 38 00 75 25 8d 4d c0 68 b0 6c 40 00 51 c6 45 fc 0c c7 45 c0 42 00 00 00 e8 e9 26 00 00 b8 39 24 40 00 c3 b8 74 24 40 00 c3 b8 45 24 40 00 c3 8b 55 ec 8b 4d e8 b8 04 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}