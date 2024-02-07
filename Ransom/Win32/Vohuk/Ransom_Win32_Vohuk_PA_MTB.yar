
rule Ransom_Win32_Vohuk_PA_MTB{
	meta:
		description = "Ransom:Win32/Vohuk.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 } //01 00  vssadmin.exe Delete Shadows /All /Quiet
		$a_01_1 = {41 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 73 00 74 00 6f 00 6c 00 65 00 6e 00 20 00 61 00 6e 00 64 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00  All your files are stolen and encrypted
		$a_01_2 = {44 6f 20 6e 6f 74 20 72 65 6e 61 6d 65 20 6f 72 20 6d 6f 64 69 66 79 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //01 00  Do not rename or modify encrypted files
		$a_01_3 = {69 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 70 61 79 20 72 61 6e 73 6f 6d } //01 00  if you do not pay ransom
		$a_01_4 = {44 65 63 72 79 70 74 69 6f 6e 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 } //00 00  Decryption of your files
	condition:
		any of ($a_*)
 
}