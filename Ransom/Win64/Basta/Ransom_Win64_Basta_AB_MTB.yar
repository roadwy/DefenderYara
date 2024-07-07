
rule Ransom_Win64_Basta_AB_MTB{
	meta:
		description = "Ransom:Win64/Basta.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 ab aa aa aa 41 f7 e7 d1 ea 8d 04 52 0f b6 54 24 90 01 01 44 2b f8 41 c1 e8 90 01 01 33 c0 41 0f be cf 33 4c 24 90 01 01 41 0b cc 39 4d 90 01 01 0f 94 c0 33 c9 31 05 90 01 04 8b 44 24 90 01 01 0b 45 f0 89 44 24 90 01 01 89 05 90 01 04 85 c9 74 90 00 } //10
		$a_01_1 = {70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 62 79 70 61 73 73 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e 20 25 73 22 } //1 process call create "powershell -executionpolicy bypass -nop -w hidden %s"
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}