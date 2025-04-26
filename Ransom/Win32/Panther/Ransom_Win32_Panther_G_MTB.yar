
rule Ransom_Win32_Panther_G_MTB{
	meta:
		description = "Ransom:Win32/Panther.G!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {70 61 6e 74 68 65 72 31 32 33 34 35 36 37 38 39 } //1 panther123456789
		$a_01_1 = {39 38 37 36 35 34 33 32 31 70 61 6e 74 68 65 72 } //1 987654321panther
		$a_01_2 = {23 62 69 74 6b 65 79 } //1 #bitkey
		$a_01_3 = {4c 4f 43 4b 45 44 5f 52 45 41 44 4d 45 } //1 LOCKED_README
		$a_01_4 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 vssadmin delete shadows /all /quiet
		$a_01_5 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 20 2f 6e 6f 69 6e 74 65 72 61 63 74 69 76 65 } //1 wmic shadowcopy delete /nointeractive
		$a_01_6 = {2e 70 61 6e 74 68 65 72 } //1 .panther
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}