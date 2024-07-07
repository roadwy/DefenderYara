
rule Ransom_Win32_Filecoder_FD_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 75 73 69 6e 67 20 32 35 36 2d 62 69 74 20 41 64 76 61 6e 63 65 64 20 45 6e 63 72 79 70 74 69 6f 6e 20 53 74 61 6e 64 61 72 64 } //1 File has been encrypted using 256-bit Advanced Encryption Standard
		$a_81_1 = {75 6e 6b 6e 6f 77 6e 64 6c 6c 2e 70 64 62 } //1 unknowndll.pdb
		$a_81_2 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 } //1 FindFirstFileA
		$a_81_3 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 57 } //1 FindNextFileW
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}