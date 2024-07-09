
rule TrojanDownloader_Win32_Chepvil_A{
	meta:
		description = "TrojanDownloader:Win32/Chepvil.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {41 fc 20 26 ce 6e e7 fa a6 b3 4e e7 b2 01 58 b1 d3 82 5d 2e 67 a9 fd 04 f3 23 5c ff 17 8b 36 57 91 73 38 f0 10 f3 24 e9 3a f0 fe 7d 85 40 72 7f e7 f9 cd b7 ce bc 23 e6 b3 02 5b 39 3d 6b 32 b8 b5 2b 3b 65 9d d6 85 b9 0a b3 08 d7 9a 91 ac 4f d1 d2 2a 6e 69 d8 fc 6c 60 1b ca fb 7f 41 51 4f 17 5a 07 26 ae 20 5c 7e c6 1d 2f e4 64 6e 3f a2 39 f1 12 d8 fd c6 c4 73 e2 78 37 1a ff 5d 2c 80 d0 c1 fd 10 0a de f1 62 } //1
		$a_01_1 = {03 57 a1 bd 73 25 62 c0 b6 23 e6 f1 50 53 fc 5e 09 c1 0f 1f 3e c3 70 25 35 28 1c a5 42 76 87 a8 62 e8 a4 3c 1e 62 9a 15 51 a4 b6 ec 59 0d 45 2a 0f 92 8a 9f 0d } //1
		$a_01_2 = {d3 c9 33 c1 8a 0a 83 c2 01 0a c9 75 f3 c9 c2 04 00 } //1
		$a_01_3 = {41 00 6a 00 68 80 00 00 00 6a 03 6a 00 6a 03 68 00 00 00 80 ff 35 } //1
		$a_03_4 = {40 00 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 68 ?? ?? 40 00 } //1
		$a_01_5 = {30 00 43 72 65 61 74 65 46 69 6c 65 41 00 46 00 43 72 65 61 74 65 54 68 72 65 61 64 } //1 0牃慥整楆敬AF牃慥整桔敲摡
		$a_00_6 = {53 6c 65 65 70 } //1 Sleep
		$a_00_7 = {63 3a 5c 6e 74 6c 64 72 } //1 c:\ntldr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}