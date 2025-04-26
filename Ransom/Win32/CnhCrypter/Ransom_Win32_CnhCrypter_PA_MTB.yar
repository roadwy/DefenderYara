
rule Ransom_Win32_CnhCrypter_PA_MTB{
	meta:
		description = "Ransom:Win32/CnhCrypter.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 79 6f 75 20 77 61 6e 74 20 62 61 63 6b 20 79 6f 75 72 20 66 69 6c 65 73 20 77 72 69 74 65 20 74 6f 3a 20 68 65 6c 70 65 72 2e 63 68 69 6e 61 40 61 6f 6c 2e 63 6f 6d } //1 If you want back your files write to: helper.china@aol.com
		$a_01_1 = {52 45 41 44 4d 45 2e 74 78 74 } //1 README.txt
		$a_01_2 = {4c 6f 63 61 6c 5c 52 75 73 74 42 61 63 6b 74 72 61 63 65 4d 75 74 65 78 } //1 Local\RustBacktraceMutex
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}