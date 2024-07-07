
rule Ransom_Win32_PlayCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/PlayCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c3 02 83 fb 08 7c 90 02 04 8b 5d 90 01 01 8b ca 83 e1 07 f6 d0 32 44 0d 90 01 01 88 04 16 42 89 55 90 01 01 3b 55 90 01 01 0f 82 90 00 } //1
		$a_03_1 = {0f b7 f9 0f af fe c7 45 90 02 06 89 7d 90 01 01 8b 7d 90 01 01 33 db 8b 55 90 01 01 8b cf 83 e1 07 89 5d 90 01 01 47 89 7d 90 01 01 8a 4c 0d 90 01 01 32 c8 88 0a 42 8b 4d 90 01 01 89 55 90 01 01 3b 7d 90 01 01 0f 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}