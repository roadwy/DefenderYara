
rule Ransom_Win64_Ryuk_PG_MTB{
	meta:
		description = "Ransom:Win64/Ryuk.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 00 79 00 75 00 6b 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 RyukReadMe.html
		$a_01_1 = {2e 00 52 00 59 00 4b 00 } //1 .RYK
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 22 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 cmd.exe /c "vssadmin.exe Delete Shadows /all /quiet
		$a_01_3 = {6e 00 74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 } //1 ntaskkill
		$a_01_4 = {63 6d 64 2e 65 78 65 20 2f 63 20 22 57 4d 49 43 2e 65 78 65 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //1 cmd.exe /c "WMIC.exe shadowcopy delete
		$a_01_5 = {72 65 70 61 63 6f 6d 72 65 31 39 37 32 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 repacomre1972@protonmail.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}