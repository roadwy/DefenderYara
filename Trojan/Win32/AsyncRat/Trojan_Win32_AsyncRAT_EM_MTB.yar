
rule Trojan_Win32_AsyncRAT_EM_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 53 43 20 4d 49 4e 55 54 45 20 2f 4d 4f 20 31 35 20 2f 54 4e } //1 schtasks /Create /SC MINUTE /MO 15 /TN
		$a_81_1 = {4d 79 4c 6f 61 64 65 72 2e 62 61 74 } //1 MyLoader.bat
		$a_81_2 = {43 6f 6c 6c 61 70 73 65 43 68 65 63 6b 5f 70 72 6f 74 65 63 74 65 64 76 2e 65 78 65 } //1 CollapseCheck_protectedv.exe
		$a_81_3 = {43 3a 5c 50 61 74 68 5c 54 6f 5c 59 6f 75 72 41 70 70 2e 65 78 65 } //1 C:\Path\To\YourApp.exe
		$a_81_4 = {41 77 64 66 74 67 34 67 72 67 35 67 35 62 66 34 35 68 72 67 65 66 65 67 34 72 67 74 34 62 72 68 35 35 72 62 64 67 64 67 } //1 Awdftg4grg5g5bf45hrgefeg4rgt4brh55rbdgdg
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}