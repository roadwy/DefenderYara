
rule Trojan_Win32_LummaStealz_AA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealz.AA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5a 76 7a 40 f8 f0 f7 94 4d ce 88 ce 86 c8 67 18 55 63 c1 36 30 b8 39 ba aa 22 90 b8 b9 ae 34 35 53 b4 42 d7 d4 6e c7 cd 60 ff 16 a9 3c b2 51 bf 28 3e 79 3b 28 c0 c7 2a 3d c6 66 31 24 8a ca 57 34 cd cd d7 c1 } //1
		$a_01_1 = {b0 9a eb 52 7c d3 2c bd ab 16 93 3a 3d af 64 c6 26 76 c9 67 e3 16 5d 18 0a 0c 8f f6 c1 5a cd d9 17 2b d1 06 45 f4 81 d3 2e 77 7c e8 6e 87 6a 7f e6 b0 9f cb 57 42 e5 70 6c 44 5f 5a 1b 88 a9 9b 78 1e 10 07 47 9b f1 a4 60 a8 ea 83 1c 5b ef 50 12 3e 20 a2 99 e7 ae 39 a8 40 16 99 80 5d 83 70 7c e8 70 fa 6a a5 ee b8 16 96 13 1a 2c 05 80 a0 ca bd 93 4d e0 12 0a ae aa cf f3 12 a7 30 fe 60 c6 37 36 1d 77 20 44 39 a9 a2 47 82 2a d4 39 82 cc 57 fe 66 64 7e 98 78 e4 24 e6 d8 b0 df 22 fe 41 74 a0 27 dc a0 ec c9 b2 8a 0e c6 de cc 1c 95 63 87 b2 2f bc f2 0f a4 59 09 92 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}