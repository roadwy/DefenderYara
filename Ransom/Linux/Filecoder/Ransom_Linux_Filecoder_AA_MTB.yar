
rule Ransom_Linux_Filecoder_AA_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.AA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 72 6f 6f 74 2f 73 6f 75 67 6f 6c 6f 63 6b 2d 6c 69 6e 75 78 2e 67 6f } //1 /root/sougolock-linux.go
		$a_01_1 = {48 89 bc 24 88 00 00 00 48 89 74 24 68 48 01 f8 48 89 04 24 48 89 54 24 08 48 89 4c 24 10 e8 0a 44 f6 ff 48 8b 44 24 58 48 8b 8c 24 b8 00 00 00 48 8b 94 24 a8 00 00 00 48 8b 9c 24 b0 00 00 00 48 8b b4 24 c0 00 00 00 48 8b bc 24 88 00 00 00 4c 8b 44 24 78 4c 8b 4c 24 68 4c 8b 94 24 80 00 00 00 48 89 d3 48 89 c6 48 89 cf 4c 8b 84 24 b0 00 00 00 4c 8b 8c 24 c0 00 00 00 4c 89 d0 48 8b 4c 24 68 48 8b 54 24 78 4c 8b 94 24 88 00 00 00 48 39 f8 } //1
		$a_01_2 = {6d 61 69 6e 2e 68 61 73 53 75 66 66 69 78 } //1 main.hasSuffix
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}