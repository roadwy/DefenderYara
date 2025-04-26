
rule Trojan_Win32_Pony_DAX_MTB{
	meta:
		description = "Trojan:Win32/Pony.DAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1b ae ec ba bb af 69 11 42 32 47 b8 bd 5e ab 9f 44 c1 a3 42 c9 12 b6 73 32 7a 67 a0 82 bc 56 b8 45 3b 61 4b e7 64 95 a8 44 42 a9 4e 1d 77 ff 51 41 be cd 84 09 11 } //1
		$a_01_1 = {46 31 5d ca a4 47 29 4a d0 ab 2d 22 49 07 0a d0 cd b8 04 dd b0 6f 87 a9 e9 33 80 e7 67 90 38 43 c8 41 0c 48 90 99 7d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}