
rule Ransom_Win64_Encoder_NE_MTB{
	meta:
		description = "Ransom:Win64/Encoder.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 89 f9 48 89 6c 24 40 45 31 c9 48 89 c3 4c 8d 44 24 60 31 d2 f3 0f 7e 05 a0 97 00 00 48 8d 05 19 96 00 00 c7 43 18 00 00 00 00 48 89 44 24 48 48 8d 05 25 96 00 00 } //2
		$a_01_1 = {c6 46 02 00 48 8d 5c 24 20 49 89 f0 48 8d 15 04 98 00 00 48 89 d9 48 8d ac 24 40 02 00 00 } //1
		$a_01_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 72 65 63 6f 76 65 72 79 2e 65 78 65 } //1 C:\WINDOWS\SYSTEM32\recovery.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}