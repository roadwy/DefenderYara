
rule Ransom_Win64_Sarcoma_BAA_MTB{
	meta:
		description = "Ransom:Win64/Sarcoma.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_81_0 = {46 41 49 4c 5f 53 54 41 54 45 5f 4e 4f 54 49 46 49 43 41 54 49 4f 4e 2e 70 64 66 } //1 FAIL_STATE_NOTIFICATION.pdf
		$a_03_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-38] 2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00 3f 00 } //1
		$a_03_2 = {68 74 74 70 3a 2f 2f [0-38] 2e 6f 6e 69 6f 6e 2f 3f } //1
		$a_81_3 = {74 6f 72 20 62 72 6f 77 73 65 72 } //1 tor browser
		$a_81_4 = {53 74 6f 6c 65 6e } //1 Stolen
		$a_81_5 = {2e 6c 6f 63 6b } //1 .lock
		$a_81_6 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 77 20 68 20 2d 63 20 53 74 61 72 74 2d 53 6c 65 65 70 20 2d 53 65 63 6f 6e 64 73 20 35 3b 20 52 65 6d 6f 76 65 2d 49 74 65 6d 20 2d 46 6f 72 63 65 20 2d 50 61 74 68 } //1 powershell -w h -c Start-Sleep -Seconds 5; Remove-Item -Force -Path
	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=6
 
}