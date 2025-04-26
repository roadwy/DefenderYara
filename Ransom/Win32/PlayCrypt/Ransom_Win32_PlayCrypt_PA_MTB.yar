
rule Ransom_Win32_PlayCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/PlayCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c3 02 83 fb 08 7c [0-04] 8b 5d ?? 8b ca 83 e1 07 f6 d0 32 44 0d ?? 88 04 16 42 89 55 ?? 3b 55 ?? 0f 82 } //1
		$a_03_1 = {0f b7 f9 0f af fe c7 45 [0-06] 89 7d ?? 8b 7d ?? 33 db 8b 55 ?? 8b cf 83 e1 07 89 5d ?? 47 89 7d ?? 8a 4c 0d ?? 32 c8 88 0a 42 8b 4d ?? 89 55 ?? 3b 7d ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}