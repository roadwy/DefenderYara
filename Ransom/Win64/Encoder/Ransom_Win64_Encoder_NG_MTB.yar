
rule Ransom_Win64_Encoder_NG_MTB{
	meta:
		description = "Ransom:Win64/Encoder.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {48 89 42 10 48 8b 0d ea 70 0f 00 8b 45 fc 48 63 d0 48 89 d0 48 c1 e0 02 48 01 d0 48 c1 e0 03 48 01 c8 49 89 c0 48 8b 55 d8 48 8b 45 c0 8b 4d f8 4d 89 c1 41 89 c8 48 89 c1 48 8b 05 b5 89 0f 00 ff d0 } //2
		$a_01_1 = {21 21 21 5f 52 45 41 44 5f 4d 45 5f 49 4d 50 4f 52 54 41 4e 54 5f 21 21 21 2e 74 78 74 } //1 !!!_READ_ME_IMPORTANT_!!!.txt
		$a_01_2 = {41 4c 50 48 41 5f 45 4e 43 52 59 50 54 45 44 } //1 ALPHA_ENCRYPTED
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 taskkill /f /im explorer.exe
		$a_01_4 = {48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 22 20 2f 76 20 44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware
		$a_01_5 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //1 DisableRegistryTools
		$a_01_6 = {43 59 42 45 52 20 53 45 43 55 52 49 54 59 20 4c 4f 43 4b 44 4f 57 4e } //1 CYBER SECURITY LOCKDOWN
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}