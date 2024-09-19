
rule Ransom_Win32_Tescrypt_NA_MTB{
	meta:
		description = "Ransom:Win32/Tescrypt.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {6f 71 77 79 34 66 71 68 75 6b 66 6c 5b 71 5b 65 72 39 66 68 70 71 65 79 38 70 66 69 39 5b 71 77 65 66 38 39 68 6a 75 } //3 oqwy4fqhukfl[q[er9fhpqey8pfi9[qwef89hju
		$a_81_1 = {47 65 74 53 68 65 6c 6c 57 69 6e 64 6f 77 } //2 GetShellWindow
		$a_81_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}