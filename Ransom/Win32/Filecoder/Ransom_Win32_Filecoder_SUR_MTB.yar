
rule Ransom_Win32_Filecoder_SUR_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.SUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {4b 49 4c 4c 5f 41 50 50 53 5f 45 4e 43 52 59 50 54 5f 41 47 41 49 4e } //2 KILL_APPS_ENCRYPT_AGAIN
		$a_01_1 = {38 43 38 42 38 46 38 46 2d 43 32 37 33 2d 34 30 44 35 2d 38 41 30 45 2d 30 37 43 45 33 39 42 46 41 38 42 42 } //2 8C8B8F8F-C273-40D5-8A0E-07CE39BFA8BB
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Ransom_Win32_Filecoder_SUR_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.SUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //2 Your files have been encrypted!
		$a_01_1 = {6c 6f 6f 6b 20 61 74 20 61 6e 79 20 66 69 6c 65 20 77 69 74 68 20 2e 72 61 7a 20 65 78 74 65 6e 73 69 6f 6e } //2 look at any file with .raz extension
		$a_01_2 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 } //1 AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}