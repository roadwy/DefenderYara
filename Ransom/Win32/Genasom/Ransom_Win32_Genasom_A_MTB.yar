
rule Ransom_Win32_Genasom_A_MTB{
	meta:
		description = "Ransom:Win32/Genasom.A!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 taskkill /f /im explorer.exe
		$a_01_2 = {5c 53 79 73 74 65 6d 50 72 6f 63 65 73 73 2e 65 78 65 } //1 \SystemProcess.exe
		$a_01_3 = {42 6c 6f 71 75 65 6f 20 64 65 6c 20 53 69 73 74 65 6d 61 } //1 Bloqueo del Sistema
		$a_01_4 = {54 75 20 73 69 73 74 65 6d 61 20 68 61 20 73 69 64 6f 20 62 6c 6f 71 75 65 61 64 6f } //1 Tu sistema ha sido bloqueado
		$a_01_5 = {53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 41 } //1 SHGetFolderPathA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}