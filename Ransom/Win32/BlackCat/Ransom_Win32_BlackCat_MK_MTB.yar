
rule Ransom_Win32_BlackCat_MK_MTB{
	meta:
		description = "Ransom:Win32/BlackCat.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //1 expand 32-byte k
		$a_81_1 = {4c 6f 63 61 6c 5c 52 75 73 74 42 61 63 6b 74 72 61 63 65 4d 75 74 65 78 } //1 Local\RustBacktraceMutex
		$a_81_2 = {45 6c 65 76 61 74 69 6f 6e 3a 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 21 6e 65 77 3a 00 00 7b 33 45 35 46 43 37 46 39 2d 39 41 35 31 2d 34 33 36 37 2d 39 30 36 33 2d 41 31 32 30 32 34 34 46 42 45 43 37 7d } //1
		$a_81_3 = {5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 \explorer.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}