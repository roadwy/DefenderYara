
rule Backdoor_Win32_Sacto_B_dha{
	meta:
		description = "Backdoor:Win32/Sacto.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 00 79 00 73 00 74 00 65 00 6e 00 26 00 63 00 70 00 3d 00 25 00 73 00 26 00 6c 00 6f 00 67 00 3d 00 25 00 73 00 26 00 69 00 6e 00 64 00 65 00 78 00 3d 00 25 00 64 00 } //5 systen&cp=%s&log=%s&index=%d
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 30 29 } //1 Microsoft Internet Explorer (compatible; MSIE 6.0; Windows NT 5.0)
		$a_01_2 = {69 00 6e 00 64 00 65 00 78 00 2e 00 61 00 73 00 70 00 3d 00 25 00 73 00 26 00 75 00 72 00 3d 00 25 00 73 00 26 00 63 00 70 00 3d 00 25 00 73 00 26 00 6f 00 73 00 3d 00 25 00 73 00 26 00 } //5 index.asp=%s&ur=%s&cp=%s&os=%s&
		$a_01_3 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 35 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 30 29 } //1 Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 5.0)
		$a_01_4 = {5c 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 2e 6c 6e 6b } //5 \Windows Update.lnk
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 55 73 65 72 20 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //2 Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5+(#a_01_5  & 1)*2) >=13
 
}