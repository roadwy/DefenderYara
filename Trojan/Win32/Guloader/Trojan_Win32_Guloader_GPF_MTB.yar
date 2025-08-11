
rule Trojan_Win32_Guloader_GPF_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {67 65 72 6d 6c 69 6e 67 } //1 germling
		$a_81_1 = {70 61 75 6c 65 74 74 65 } //1 paulette
		$a_81_2 = {72 61 6f 75 6c 69 61 20 67 77 65 64 75 63 6b 73 20 75 64 64 79 62 65 74 } //1 raoulia gweducks uddybet
		$a_81_3 = {61 74 6f 6d 66 6f 72 73 67 73 73 74 61 74 69 6f 6e 2e 65 78 65 } //1 atomforsgsstation.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}