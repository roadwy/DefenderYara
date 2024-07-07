
rule Ransom_Win32_Silvertor_SK_MTB{
	meta:
		description = "Ransom:Win32/Silvertor.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 69 6c 76 65 72 74 6f 72 } //2 silvertor
		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 66 72 69 65 64 20 69 6e } //2 Your files will be fried in
		$a_01_2 = {5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 52 45 41 44 4d 45 2e 68 74 6d 6c } //2 \Start Menu\Programs\Startup\README.html
		$a_01_3 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //15 vssadmin.exe Delete Shadows /All /Quiet
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*15) >=19
 
}