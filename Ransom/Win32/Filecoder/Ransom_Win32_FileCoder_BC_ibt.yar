
rule Ransom_Win32_FileCoder_BC_ibt{
	meta:
		description = "Ransom:Win32/FileCoder.BC!ibt,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //vssadmin.exe Delete Shadows /all /quiet  1
		$a_80_1 = {77 6d 69 63 2e 65 78 65 20 53 68 61 64 6f 77 63 6f 70 79 20 44 65 6c 65 74 65 } //wmic.exe Shadowcopy Delete  1
		$a_80_2 = {69 69 73 72 65 73 65 74 2e 65 78 65 20 2f 73 74 6f 70 } //iisreset.exe /stop  1
		$a_80_3 = {5a 67 42 76 41 48 49 41 5a 51 42 68 41 47 4d 41 61 41 41 67 41 43 67 41 4a 41 42 70 41 43 41 41 61 51 42 75 41 43 41 41 4a 41 41 6f 41 47 4d 41 62 51 42 6b 41 43 34 41 5a 51 42 34 41 47 55 41 49 41 41 76 41 47 4d 41 49 41 42 7a 41 47 4d } //ZgBvAHIAZQBhAGMAaAAgACgAJABpACAAaQBuACAAJAAoAGMAbQBkAC4AZQB4AGUAIAAvAGMAIABzAGM  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}