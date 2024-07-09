
rule Ransom_Win32_Ryuk_AA_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {55 89 e5 8b 45 0c 8b 55 08 89 d1 09 c1 8b 45 0c 8b 55 08 21 d0 f7 d0 21 c8 5d c3 } //1
		$a_02_1 = {8b 45 f0 8b 55 0c 01 d0 8a 00 0f be c0 89 44 24 04 8b 45 e8 89 04 24 e8 ?? ?? ff ff 88 03 ff 45 f0 8b 45 f0 3b 45 ec 0f 92 c0 84 c0 0f 85 ?? ff ff ff } //1
		$a_00_2 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 41 } //1 CryptAcquireContextA
		$a_00_3 = {50 49 4d 41 47 45 5f 54 4c 53 5f 43 41 4c 4c 42 41 43 4b } //1 PIMAGE_TLS_CALLBACK
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}