
rule Ransom_Win32_Filecoder_VKY_MSR{
	meta:
		description = "Ransom:Win32/Filecoder.VKY!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 ad 8b d0 0f ca b9 04 00 00 00 33 c0 0f a4 d0 06 d7 aa c1 c2 06 e2 f3 4e 59 e2 e4 } //1
		$a_01_1 = {8b df b9 f4 00 00 00 89 4d d4 fc f3 a4 68 00 05 00 00 8d 45 d4 50 53 6a 00 6a 00 6a 00 ff 35 04 38 40 00 e8 11 05 00 00 83 c7 0c ff 4d cc 75 d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}