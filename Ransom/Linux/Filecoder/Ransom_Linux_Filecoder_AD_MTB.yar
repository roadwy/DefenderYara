
rule Ransom_Linux_Filecoder_AD_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.AD!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 41 57 41 56 41 55 41 54 53 50 48 89 fb 48 8b 77 08 48 85 f6 74 12 48 8b 3b 48 c1 e6 04 ba 08 00 00 00 ff 15 27 90 0b 00 4c 8b 73 18 4c 8b 6b 28 49 ff c5 4c 89 f7 } //1
		$a_01_1 = {48 89 fb 48 8b 0f 48 8b 7f 08 48 89 f8 48 29 c8 48 be ab aa aa aa aa aa aa aa 48 f7 e6 48 8d 05 83 6f fc ff 48 89 03 48 89 43 08 4c 8b 7b 10 48 39 cf 74 54 49 89 d6 49 c1 ee 04 49 8b 3f 48 29 f9 48 89 c8 48 f7 e6 48 c1 ea 04 48 8d 04 52 4c 8d 24 c7 49 83 c4 08 4c 8b 2d e9 c7 0b 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}