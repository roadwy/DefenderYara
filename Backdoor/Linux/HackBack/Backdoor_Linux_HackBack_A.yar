
rule Backdoor_Linux_HackBack_A{
	meta:
		description = "Backdoor:Linux/HackBack.A,SIGNATURE_TYPE_MACHOHSTR_EXT,0e 00 0e 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 42 61 63 6b 75 70 2e 69 6e 69 } //2 FileBackup.ini
		$a_03_1 = {63 68 65 63 6b 41 75 74 6f 72 75 6e 90 02 05 61 70 70 6c 69 63 61 74 69 6f 6e 57 69 6c 6c 54 65 72 6d 69 6e 61 74 65 3a 90 00 } //2
		$a_01_2 = {6d 5f 43 6f 6d 70 75 74 65 72 4e 61 6d 65 5f 55 73 65 72 4e 61 6d 65 } //2 m_ComputerName_UserName
		$a_01_3 = {6d 5f 75 70 6c 6f 61 64 55 52 4c } //2 m_uploadURL
		$a_01_4 = {6d 5f 46 6f 6c 64 65 72 4c 69 73 74 } //2 m_FolderList
		$a_01_5 = {63 6f 6e 6e 65 63 74 73 65 72 76 65 72 5f 63 61 6c 6c 62 61 63 6b } //2 connectserver_callback
		$a_01_6 = {44 61 74 65 2e 64 61 74 00 46 61 69 6c 2e 64 61 74 } //2
		$a_01_7 = {2f 75 70 6c 6f 61 64 2e 70 68 70 } //2 /upload.php
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=14
 
}