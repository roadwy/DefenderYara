
rule Ransom_Win32_FileCryptor_PC_MTB{
	meta:
		description = "Ransom:Win32/FileCryptor.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 44 65 73 6b 74 6f 70 5c 52 45 41 44 4d 45 2e 74 78 74 } //1 \Desktop\README.txt
		$a_01_1 = {6e 65 74 20 75 73 65 72 20 2f 61 64 64 20 52 65 64 52 4f 4d 41 4e 20 70 34 7a 7a 61 75 62 37 31 68 } //1 net user /add RedROMAN p4zzaub71h
		$a_01_2 = {5c 44 65 73 6b 74 6f 70 5c 45 4e 54 45 52 2d 50 41 53 53 57 4f 52 44 2d 48 45 52 45 2e 74 78 74 } //1 \Desktop\ENTER-PASSWORD-HERE.txt
		$a_01_3 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 vssadmin.exe Delete Shadows /All /Quiet
		$a_01_4 = {5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 52 45 41 44 4d 45 2e 68 74 6d 6c } //1 \Start Menu\Programs\Startup\README.html
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}