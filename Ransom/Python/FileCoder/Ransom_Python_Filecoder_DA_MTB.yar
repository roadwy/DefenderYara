
rule Ransom_Python_Filecoder_DA_MTB{
	meta:
		description = "Ransom:Python/Filecoder.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd6 00 ffffffd6 00 09 00 00 "
		
	strings :
		$a_81_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 } //100 powershell -C
		$a_81_1 = {53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 } //100 Set-MpPreference
		$a_81_2 = {2d 53 75 62 6d 69 74 53 61 6d 70 6c 65 73 43 6f 6e 73 65 6e 74 20 4e 65 76 65 72 53 65 6e 64 } //10 -SubmitSamplesConsent NeverSend
		$a_81_3 = {2d 4d 41 50 53 52 65 70 6f 72 74 69 6e 67 20 44 69 73 61 62 6c 65 } //10 -MAPSReporting Disable
		$a_81_4 = {2d 45 6e 61 62 6c 65 43 6f 6e 74 72 6f 6c 6c 65 64 46 6f 6c 64 65 72 41 63 63 65 73 73 20 44 69 73 61 62 6c 65 64 } //10 -EnableControlledFolderAccess Disabled
		$a_81_5 = {77 69 6e 64 6f 77 73 20 64 65 66 65 6e 64 65 72 20 65 76 61 73 69 6f 6e 20 73 75 63 63 65 73 73 66 75 6c 6c } //1 windows defender evasion successfull
		$a_81_6 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 taskkill /f /im explorer.exe
		$a_81_7 = {65 6e 63 72 79 70 74 65 64 5f 64 61 74 61 } //1 encrypted_data
		$a_81_8 = {65 6e 63 72 79 70 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 encrypted successfully
	condition:
		((#a_81_0  & 1)*100+(#a_81_1  & 1)*100+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=214
 
}