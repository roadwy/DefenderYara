
rule Ransom_Linux_Filecoder_AB_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.AB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6f 0d 51 42 15 00 66 0f 6f 05 59 42 15 00 48 b8 7c 6f 6b 6e 2a 2f 7e 67 41 ba 2a 2f 00 00 c6 85 5b fc ff ff 00 0f 29 8d d0 fd ff ff 48 89 85 50 fc ff ff 0f 29 85 e0 fd ff ff 66 44 89 95 58 fc ff ff 48 89 85 f0 fd ff ff c6 85 5a fc ff ff 80 8b 85 58 fc ff ff 0f 29 8d 30 fc ff ff 89 85 f8 fd ff ff 31 c0 0f 29 85 40 fc ff ff 0f 1f 00 } //1
		$a_01_1 = {0f b6 94 05 20 fd ff ff 83 ea 04 88 94 05 20 fd ff ff 48 83 c0 01 48 83 f8 2a 75 e4 e8 1f 4e 02 00 4c 8b a0 30 01 00 00 41 8b 5c 24 40 45 0f b6 b4 24 90 00 00 00 83 fb 02 0f 8e 31 32 00 00 45 84 f6 0f 85 28 32 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}