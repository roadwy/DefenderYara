
rule TrojanSpy_Win32_Pophot_G{
	meta:
		description = "TrojanSpy:Win32/Pophot.G,SIGNATURE_TYPE_PEHSTR,3d 00 3d 00 08 00 00 "
		
	strings :
		$a_01_0 = {7a 75 6f 79 75 65 31 36 2e 69 6e 69 } //1 zuoyue16.ini
		$a_01_1 = {73 2e 69 6e 69 } //1 s.ini
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e } //10 Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\run
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //10 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_01_4 = {41 56 50 2e 41 } //10 AVP.A
		$a_01_5 = {41 56 50 2e 50 72 6f 64 75 63 74 5f 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //10 AVP.Product_Notification
		$a_01_6 = {41 56 50 2e 54 72 61 66 66 69 63 4d 6f 6e 43 6f 6e 6e 65 63 74 69 6f 6e 54 65 72 6d } //10 AVP.TrafficMonConnectionTerm
		$a_01_7 = {2e 6c 6e 6b } //10 .lnk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10) >=61
 
}