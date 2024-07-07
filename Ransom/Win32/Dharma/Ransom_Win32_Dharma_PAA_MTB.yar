
rule Ransom_Win32_Dharma_PAA_MTB{
	meta:
		description = "Ransom:Win32/Dharma.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 00 48 00 41 00 52 00 4d 00 41 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 } //5 DHARMADECRYPT
		$a_01_1 = {73 63 68 74 61 73 6b 73 20 2f 43 52 45 41 54 45 20 2f 53 43 20 4f 4e 4c 4f 47 4f 4e 20 2f 54 4e 20 44 48 41 52 4d 41 20 2f 54 52 } //5 schtasks /CREATE /SC ONLOGON /TN DHARMA /TR
		$a_01_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_01_3 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 DisableAntiSpyware
		$a_01_4 = {73 74 61 72 74 20 63 6d 64 2e 65 78 65 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 74 20 2f 66 20 2f 69 6d } //1 start cmd.exe /c taskkill /t /f /im
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}