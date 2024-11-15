
rule HackTool_Win64_AutoKms_DZ_MTB{
	meta:
		description = "HackTool:Win64/AutoKms.DZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_81_0 = {6b 6d 73 2e 6b 6d 7a 73 31 32 33 2e 63 6e } //2 kms.kmzs123.cn
		$a_81_1 = {4f 66 66 69 63 65 20 32 30 31 36 20 50 6f 77 65 72 50 6f 69 6e 74 56 4c 20 4b 4d 53 20 43 6c 69 65 6e 74 } //2 Office 2016 PowerPointVL KMS Client
		$a_81_2 = {61 64 64 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 43 6f 6d 6d 6f 6e 5c 43 6c 69 65 6e 74 54 65 6c 65 6d 65 74 72 79 22 20 2f 76 20 22 44 69 73 61 62 6c 65 54 65 6c 65 6d 65 74 72 79 22 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //2 add "HKCU\Software\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
		$a_81_3 = {2f 2f 4e 6f 4c 6f 67 6f 20 2f 75 6e 70 6b 65 79 3a } //1 //NoLogo /unpkey:
		$a_81_4 = {41 43 54 49 56 41 54 45 } //1 ACTIVATE
		$a_81_5 = {4f 66 66 69 63 65 20 32 30 31 30 20 52 54 4d 20 53 74 61 6e 64 61 72 64 20 4b 4d 53 20 43 6c 69 65 6e 74 } //2 Office 2010 RTM Standard KMS Client
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*2) >=10
 
}