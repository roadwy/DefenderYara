
rule Ransom_Win64_GoAgendaCrypt_AD_MTB{
	meta:
		description = "Ransom:Win64/GoAgendaCrypt.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 32 35 56 73 49 67 52 44 72 } //01 00  Y25VsIgRDr
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 65 6e 63 2e 65 78 65 } //01 00  C:\Users\Public\enc.exe
		$a_01_2 = {45 6e 61 62 6c 65 4c 69 6e 6b 65 64 43 6f 6e 6e 65 63 74 69 6f 6e 73 } //01 00  EnableLinkedConnections
		$a_01_3 = {4c 6f 67 6f 6e 55 73 65 72 57 } //01 00  LogonUserW
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
	condition:
		any of ($a_*)
 
}