
rule Trojan_Win64_Remcos_ARO_MTB{
	meta:
		description = "Trojan:Win64/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 85 74 0a 00 00 4d c6 85 75 0a 00 00 dc c6 85 76 0a 00 00 00 c6 85 77 0a 00 00 b0 c6 85 78 0a 00 00 15 c6 85 79 0a 00 00 ce c6 85 7a 0a 00 00 4e c6 85 7b 0a 00 00 0a c6 85 7c 0a 00 00 c9 c6 85 7d 0a 00 00 c6 c6 85 7e 0a 00 00 d4 c6 85 7f 0a 00 00 25 c6 85 80 0a 00 00 14 c6 85 81 0a 00 00 27 c6 85 82 0a 00 00 ab c6 85 83 0a 00 00 55 c6 85 84 0a 00 00 67 c6 85 85 0a 00 00 3c c6 85 86 0a 00 00 80 c6 85 87 0a 00 00 76 c6 85 88 0a 00 00 c1 c6 85 89 0a 00 00 6f c6 85 8a 0a 00 00 37 c6 85 8b 0a 00 00 e8 c6 85 8c 0a 00 00 bb } //2
		$a_01_1 = {c6 85 66 0a 00 00 4d c6 85 67 0a 00 00 01 c6 85 68 0a 00 00 d9 c6 85 69 0a 00 00 cc c6 85 6a 0a 00 00 ee c6 85 6b 0a 00 00 cc c6 85 6c 0a 00 00 96 c6 85 6d 0a 00 00 42 c6 85 6e 0a 00 00 a0 c6 85 6f 0a 00 00 23 c6 85 70 0a 00 00 68 c6 85 71 0a 00 00 ae c6 85 72 0a 00 00 b8 c6 85 73 0a 00 00 9d } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}