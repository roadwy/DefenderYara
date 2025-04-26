
rule Trojan_Win32_Cosmu_DA_MTB{
	meta:
		description = "Trojan:Win32/Cosmu.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 2d 56 53 57 65 62 46 69 6c 65 2e 70 73 31 } //20 Get-VSWebFile.ps1
		$a_01_1 = {65 2e 70 73 31 } //1 e.ps1
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 4f 75 74 6c 6f 6f 6b 32 30 31 36 43 41 57 69 6e 33 32 2e 78 6d 6c } //1 MicrosoftOutlook2016CAWin32.xml
		$a_01_3 = {43 6f 6e 6e 65 63 74 69 6f 6e 73 2e 70 72 6f 76 78 6d 6c } //1 Connections.provxml
		$a_01_4 = {2e 66 69 6c 65 73 } //1 .files
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=24
 
}