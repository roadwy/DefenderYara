
rule Ransom_Win32_Wannabe_SD_MTB{
	meta:
		description = "Ransom:Win32/Wannabe.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {5c 57 61 6e 6e 61 42 65 2e 65 78 65 } //1 \WannaBe.exe
		$a_81_1 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 5f 6b 31 2e 65 78 65 } //1 \AppData\Local\Google\Chrome\_k1.exe
		$a_81_2 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 4d 53 44 61 74 61 5c 6b 32 2e 65 78 65 } //1 \AppData\Local\MSData\k2.exe
		$a_03_3 = {43 3a 5c 74 65 6d 70 5f [0-20] 5c 90 1b 00 2e 7a 69 70 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}