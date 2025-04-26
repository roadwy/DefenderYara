
rule Ransom_Win64_Albabat_YAA_MTB{
	meta:
		description = "Ransom:Win64/Albabat.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 72 69 73 75 2e 72 73 } //1 grisu.rs
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 Software\Microsoft\Windows\CurrentVersion\Policies\SystemDisableTaskMgr
		$a_01_2 = {77 61 6c 6c 70 61 70 65 72 5f 61 6c 62 61 62 61 74 2e 6a 70 67 } //1 wallpaper_albabat.jpg
		$a_01_3 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d } //1 -----BEGIN RSA PUBLIC KEY----
		$a_01_4 = {45 4e 43 52 59 50 54 45 44 } //1 ENCRYPTED
		$a_01_5 = {64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 } //1 decrypt your files
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}