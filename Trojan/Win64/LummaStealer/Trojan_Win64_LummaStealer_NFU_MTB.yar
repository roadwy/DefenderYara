
rule Trojan_Win64_LummaStealer_NFU_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.NFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //1 powershell -Command "Add-MpPreference -ExclusionPath
		$a_81_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 } //1 powershell -Command "Invoke-WebRequest -Uri
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //2 Software\Microsoft\Windows\CurrentVersion\Run
		$a_81_3 = {57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 } //1 Windows Defender
		$a_81_4 = {43 3a 5c 55 73 65 72 73 5c 64 61 6e 61 72 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 6f 70 72 65 74 6f 72 73 61 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6f 70 72 65 74 6f 72 73 61 2e 70 64 62 } //1 C:\Users\danar\source\repos\opretorsa\x64\Release\opretorsa.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}