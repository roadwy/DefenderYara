
rule Ransom_Win64_Filecoder_NIT_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 8b 74 24 70 48 8d 34 f2 48 8d b6 d8 01 01 00 49 89 c2 48 87 06 48 8b 84 24 a0 00 00 00 48 8b 8c 24 80 00 00 00 48 89 d6 4c 8b 44 24 78 49 b9 ff ff ff ff ff 7f 00 00 41 84 02 41 81 e0 ff ff 0f 00 4f 8b 1c c2 4d 85 db 0f 85 b9 01 00 00 4c 89 44 24 30 4c 89 94 24 88 00 00 00 48 8d 86 e0 03 01 00 bb d0 10 00 00 b9 08 00 00 00 48 8d 3d a5 a2 28 00 } //2
		$a_01_1 = {66 69 6c 65 77 61 6c 6b 65 72 } //2 filewalker
		$a_01_2 = {45 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //2 EncryptDirectory
		$a_01_3 = {6b 69 6c 6c 69 6e 67 20 43 6d 64 65 78 65 63 } //1 killing Cmdexec
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}