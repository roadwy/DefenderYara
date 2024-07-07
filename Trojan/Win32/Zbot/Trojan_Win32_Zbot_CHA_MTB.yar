
rule Trojan_Win32_Zbot_CHA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 65 6c 6f 64 69 65 72 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 52 61 72 24 45 58 30 30 2e 33 37 33 5c 41 76 69 73 5f 64 65 5f 50 61 69 65 6d 65 6e 74 2e 65 78 65 } //1 C:\Users\elodier\AppData\Local\Temp\Rar$EX00.373\Avis_de_Paiement.exe
		$a_81_1 = {43 3a 5c 73 61 6d 70 6c 65 2e 65 78 65 } //1 C:\sample.exe
		$a_81_2 = {43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 44 6f 77 6e 6c 6f 61 64 73 5c 66 69 6c 65 30 31 36 5f 69 65 75 70 64 61 74 65 2e 65 78 65 } //1 C:\Users\admin\Downloads\file016_ieupdate.exe
		$a_81_3 = {48 65 65 70 69 6c } //1 Heepil
		$a_81_4 = {43 3a 5c 55 73 65 72 73 5c 72 2e 76 75 6c 74 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 36 37 38 63 39 33 63 38 34 62 63 37 35 34 34 64 61 30 61 39 35 30 33 36 64 65 62 30 66 37 36 66 2e 65 78 65 } //1 C:\Users\r.vult\AppData\Local\Temp\678c93c84bc7544da0a95036deb0f76f.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}