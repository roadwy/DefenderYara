
rule Ransom_Win32_Mischa_A{
	meta:
		description = "Ransom:Win32/Mischa.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {3c 68 31 3e 59 6f 75 20 62 65 63 61 6d 65 20 76 69 63 74 69 6d 20 6f 66 20 74 68 65 20 4d 49 53 43 48 41 20 52 41 4e 53 4f 4d 57 41 52 45 21 3c 2f 68 31 3e } //2 <h1>You became victim of the MISCHA RANSOMWARE!</h1>
		$a_01_1 = {3a 2f 2f 6d 69 73 63 68 61 } //1 ://mischa
		$a_01_2 = {3c 74 69 74 6c 65 3e 4d 49 53 43 48 41 20 52 61 6e 73 6f 6d 77 61 72 65 3c 2f 74 69 74 6c 65 3e } //1 <title>MISCHA Ransomware</title>
		$a_01_3 = {4d 69 73 63 68 61 2e 64 6c 6c } //1 Mischa.dll
		$a_01_4 = {59 4f 55 52 5f 46 49 4c 45 53 5f 41 52 45 5f 45 4e 43 52 59 50 54 45 44 } //1 YOUR_FILES_ARE_ENCRYPTED
		$a_01_5 = {23 23 55 52 4c 31 23 23 3c 62 72 2f 3e 20 23 23 55 52 4c 32 23 23 } //1 ##URL1##<br/> ##URL2##
		$a_01_6 = {23 23 43 4f 44 45 23 23 20 3c 2f 62 6f 64 79 3e 3c 2f 68 74 6d 6c 3e } //1 ##CODE## </body></html>
		$a_01_7 = {00 2e 70 73 70 69 6d 61 67 65 00 } //1
		$a_01_8 = {00 5c 24 52 65 63 79 63 6c 65 2e 42 69 6e 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=4
 
}