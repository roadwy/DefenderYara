
rule Ransom_Win32_HydraCrypt_SA_MTB{
	meta:
		description = "Ransom:Win32/HydraCrypt.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 "
		
	strings :
		$a_80_0 = {40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //@tutanota.com  1
		$a_80_1 = {46 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //Files are encrypted  1
		$a_80_2 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //vssadmin.exe delete shadows /all /quiet  1
		$a_80_3 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //wmic shadowcopy delete  1
		$a_80_4 = {2f 43 20 77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } ///C wbadmin delete catalog -quiet  1
		$a_80_5 = {52 45 41 44 5f 4d 45 2e 68 74 61 } //READ_ME.hta  1
		$a_80_6 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 31 20 26 20 44 65 6c } ///C choice /C Y /N /D Y /T 1 & Del  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=6
 
}