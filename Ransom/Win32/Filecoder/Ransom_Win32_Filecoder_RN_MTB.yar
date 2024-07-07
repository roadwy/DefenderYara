
rule Ransom_Win32_Filecoder_RN_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.RN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {23 e1 ba 8a 1a e0 f4 b0 bd 09 94 88 7c 97 d4 c9 e3 e5 ff 71 4d 52 5e bc 70 e5 12 de 21 7d d8 86 d4 73 98 ed 92 be 5b 1d b9 e2 30 2f 3b a4 4c 75 da 1d 4d 33 3b ed 90 26 64 ad 4c 73 87 d4 0f 9a ed 8e 1a 79 b4 3b 8a 79 2e 56 91 22 c7 41 04 ea 0f 31 8d 50 81 c8 19 f4 9c 08 ab cd a6 1a 2b 8b f0 62 ee dc 1f 55 ae 41 fa 73 d7 8e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}