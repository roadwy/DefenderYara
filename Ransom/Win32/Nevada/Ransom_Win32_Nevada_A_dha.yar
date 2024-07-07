
rule Ransom_Win32_Nevada_A_dha{
	meta:
		description = "Ransom:Win32/Nevada.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 45 56 41 44 41 } //1 NEVADA
		$a_00_1 = {46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 72 61 6e 73 6f 6d 20 6e 6f 74 65 } //1 Failed to create ransom note
		$a_00_2 = {43 6f 75 6c 64 6e 27 74 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 20 63 6f 70 69 65 73 20 66 72 6f 6d 20 76 6f 6c 75 6d 65 21 } //1 Couldn't delete shadow copies from volume!
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}