
rule Ransom_Win32_MedusaLocker_AA_MTB{
	meta:
		description = "Ransom:Win32/MedusaLocker.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 65 64 75 73 61 5c 52 65 6c 65 61 73 65 5c 67 61 7a 65 2e 70 64 62 } //1 Medusa\Release\gaze.pdb
		$a_01_1 = {57 65 20 68 61 76 65 20 50 45 4e 45 54 52 41 54 45 20 79 6f 75 72 20 6e 65 74 77 6f 72 6b 20 61 6e 64 20 43 4f 50 49 45 44 20 64 61 74 61 } //1 We have PENETRATE your network and COPIED data
		$a_01_2 = {57 65 20 68 61 76 65 20 45 4e 43 52 59 50 54 45 44 20 73 6f 6d 65 20 79 6f 75 72 20 66 69 6c 65 73 } //1 We have ENCRYPTED some your files
		$a_01_3 = {4d 45 44 55 53 41 20 44 45 43 52 59 50 54 4f 52 20 61 6e 64 20 44 45 43 52 59 50 54 49 4f 4e 20 4b 45 59 73 } //1 MEDUSA DECRYPTOR and DECRYPTION KEYs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Ransom_Win32_MedusaLocker_AA_MTB_2{
	meta:
		description = "Ransom:Win32/MedusaLocker.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {3a 00 5c 00 24 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 } //1 :\$Windows
		$a_01_1 = {3a 00 5c 00 24 00 57 00 69 00 6e 00 52 00 45 00 41 00 67 00 65 00 6e 00 74 00 5c 00 } //1 :\$WinREAgent\
		$a_01_2 = {5b 00 2b 00 5d 00 5b 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 5d 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 3a 00 } //1 [+][Encrypt] Encrypted:
		$a_01_3 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 taskkill /f /im explorer.exe
		$a_01_4 = {72 00 65 00 6d 00 20 00 6b 00 69 00 6c 00 6c 00 } //1 rem kill
		$a_01_5 = {2d 00 73 00 68 00 61 00 72 00 65 00 73 00 3d 00 } //1 -shares=
		$a_01_6 = {73 74 75 62 5f 77 69 6e 5f 78 36 34 5f 65 6e 63 72 79 70 74 65 72 2e 70 64 62 } //1 stub_win_x64_encrypter.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}