
rule Trojan_Win32_Redosdru_B{
	meta:
		description = "Trojan:Win32/Redosdru.B,SIGNATURE_TYPE_PEHSTR,33 00 33 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 48 30 53 54 43 } //10 GH0STC
		$a_01_1 = {25 73 25 73 25 73 } //10 %s%s%s
		$a_01_2 = {25 00 73 00 5c 00 25 00 78 00 2e 00 64 00 6c 00 6c 00 } //10 %s\%x.dll
		$a_01_3 = {00 49 6e 73 74 61 6c 6c 00 } //10
		$a_01_4 = {5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62 } //10 \Release\Loader.pdb
		$a_01_5 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //1 OpenProcessToken
		$a_01_6 = {47 65 74 54 6f 6b 65 6e 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 GetTokenInformation
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=51
 
}
rule Trojan_Win32_Redosdru_B_2{
	meta:
		description = "Trojan:Win32/Redosdru.B,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74 } //5 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
		$a_01_1 = {00 00 47 68 30 73 74 20 55 70 64 61 74 65 00 00 } //5
		$a_01_2 = {25 73 5c 25 64 5f 72 65 73 2e 74 6d 70 } //1 %s\%d_res.tmp
		$a_01_3 = {52 65 67 51 75 65 72 79 56 61 6c 75 65 45 78 28 53 76 63 68 6f 73 74 5c 6e 65 74 73 76 63 73 29 } //1 RegQueryValueEx(Svchost\netsvcs)
		$a_01_4 = {41 64 64 41 63 63 65 73 73 41 6c 6c 6f 77 65 64 41 63 65 45 78 00 00 00 5c 44 72 69 76 65 72 73 } //1
		$a_01_5 = {49 6e 73 74 61 6c 6c 4d 6f 64 75 6c 65 00 00 00 4d 69 63 72 6f 73 6f 66 74 20 44 65 76 69 63 65 20 4d 61 6e 61 67 65 72 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}