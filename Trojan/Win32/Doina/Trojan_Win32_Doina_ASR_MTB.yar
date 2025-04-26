
rule Trojan_Win32_Doina_ASR_MTB{
	meta:
		description = "Trojan:Win32/Doina.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {78 c3 2e 9b 82 7f 3c a9 72 52 c7 53 78 41 53 4b d6 c2 c5 1c d1 a2 f2 69 e0 ff e6 63 91 5c 4b 6f e3 40 d9 8a 6b b9 ed c3 } //2
		$a_01_1 = {4e 95 2d 7d 93 96 42 b2 7a 8e 48 5f 83 76 22 34 22 bd 32 c9 25 02 04 b0 76 2b 31 23 1d 22 24 ff e0 86 72 e1 0d 12 b6 cf a3 4a 42 cd } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}