
rule Ransom_Win32_FileCoder_JSG_MSR{
	meta:
		description = "Ransom:Win32/FileCoder.JSG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 73 69 6e 65 7a 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 47 6f 6e 6e 61 43 6f 70 65 5c 47 6f 6e 6e 61 43 6f 70 65 43 72 79 70 74 6f 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 47 6f 6e 6e 61 43 6f 70 65 43 72 79 70 74 6f 72 2e 70 64 62 } //2 C:\Users\sinez\source\repos\GonnaCope\GonnaCopeCryptor\obj\Debug\GonnaCopeCryptor.pdb
		$a_01_1 = {43 00 6f 00 70 00 69 00 75 00 6d 00 2d 00 } //1 Copium-
		$a_01_2 = {2e 00 63 00 6f 00 70 00 65 00 } //1 .cope
		$a_00_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}