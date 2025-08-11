
rule Trojan_Win32_Stealer_NJD_MTB{
	meta:
		description = "Trojan:Win32/Stealer.NJD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {2b c8 83 e1 0f 03 c1 1b c9 0b c1 59 e9 ?? ?? ?? ?? 51 8d 4c 24 08 2b c8 83 e1 07 03 c1 1b c9 0b c1 } //2
		$a_01_1 = {49 f1 60 68 21 00 9d c1 95 3f 90 42 fb a7 65 de eb 9b b2 32 fa 19 32 91 db 06 cc d1 6e 6a 19 48 } //1
		$a_01_2 = {f0 e6 98 0f 4f 4b b7 95 85 05 f8 d2 ec 54 fd 59 5f bc 6e d7 76 91 55 59 df 06 1d 9c 5b e0 39 07 } //1
		$a_01_3 = {99 4c 95 a1 ce 78 0a 5c 91 39 69 79 c6 c7 f0 ee ce a2 f8 f5 39 da f0 09 f7 64 06 37 54 cb 92 60 } //1
		$a_01_4 = {74 d7 de 71 a6 40 82 21 a7 97 12 aa 64 69 9d 50 67 32 3f a9 cd e9 65 ec cb 95 e6 30 30 33 f2 45 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}