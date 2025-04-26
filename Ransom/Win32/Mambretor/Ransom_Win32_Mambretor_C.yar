
rule Ransom_Win32_Mambretor_C{
	meta:
		description = "Ransom:Win32/Mambretor.C,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 20 68 61 72 64 20 64 72 69 76 65 20 65 6e 63 72 79 70 74 69 6f 6e 2e 2e 2e } //10 start hard drive encryption...
		$a_01_1 = {2d 00 62 00 6f 00 6f 00 74 00 20 00 2d 00 73 00 65 00 74 00 6d 00 62 00 72 00 20 00 68 00 64 00 30 00 } //10 -boot -setmbr hd0
		$a_01_2 = {5c 00 64 00 63 00 63 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //10 \dccon.exe
		$a_01_3 = {4c 57 56 75 59 33 4a 35 63 48 51 67 63 48 51 } //1 LWVuY3J5cHQgcHQ
		$a_81_4 = {2d 65 6e 63 72 79 70 74 20 70 74 } //1 -encrypt pt
		$a_01_5 = {49 43 59 67 64 47 46 7a 61 32 74 70 62 47 77 67 4c 32 6c 74 49 45 31 76 64 57 35 30 4c 6d 56 34 5a 53 } //1 ICYgdGFza2tpbGwgL2ltIE1vdW50LmV4ZS
		$a_01_6 = {26 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 4d 6f 75 6e 74 2e 65 78 65 } //1 & taskkill /im Mount.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=31
 
}