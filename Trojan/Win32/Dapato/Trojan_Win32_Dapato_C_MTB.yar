
rule Trojan_Win32_Dapato_C_MTB{
	meta:
		description = "Trojan:Win32/Dapato.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {78 65 69 6d 5f 73 65 72 76 65 72 5f 69 6e 66 6f } //2 xeim_server_info
		$a_01_1 = {75 73 65 72 6e 61 6d 65 } //2 username
		$a_01_2 = {70 61 73 73 77 6f 72 64 } //2 password
		$a_01_3 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 75 73 65 72 69 6e 66 6f 20 57 48 45 52 45 20 75 69 64 3d 27 25 73 27 } //2 SELECT * FROM userinfo WHERE uid='%s'
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //2 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {43 3a 5c 55 73 65 72 73 5c 25 73 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 25 73 } //2 C:\Users\%s\AppData\Local\%s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}