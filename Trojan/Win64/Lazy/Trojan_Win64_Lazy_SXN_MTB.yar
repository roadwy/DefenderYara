
rule Trojan_Win64_Lazy_SXN_MTB{
	meta:
		description = "Trojan:Win64/Lazy.SXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 07 00 00 "
		
	strings :
		$a_80_0 = {73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 54 4e 20 22 4d 69 63 72 6f 73 6f 66 74 45 64 67 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 43 6f 72 65 22 20 2f 58 4d 4c 20 } //schtasks /Create /TN "MicrosoftEdgeUpdateTaskMachineCore" /XML   10
		$a_80_1 = {73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 54 4e 20 22 57 69 6e 64 6f 77 73 53 65 63 75 72 69 74 79 48 65 61 6c 74 68 53 65 72 76 69 63 65 22 20 2f 58 4d 4c 20 } //schtasks /Create /TN "WindowsSecurityHealthService" /XML   10
		$a_80_2 = {69 66 20 28 24 5f 2e 45 78 63 65 70 74 69 6f 6e 2e 52 65 73 70 6f 6e 73 65 2e 53 74 61 74 75 73 43 6f 64 65 20 2d 65 71 20 34 30 34 29 20 7b 20 65 78 69 74 20 34 34 20 7d 20 65 6c 73 65 20 7b 20 65 78 69 74 20 31 20 7d } //if ($_.Exception.Response.StatusCode -eq 404) { exit 44 } else { exit 1 }  5
		$a_80_3 = {63 6c 69 65 6e 74 5f 74 61 73 6b 5f 73 79 73 74 65 6d 2e 78 6d 6c } //client_task_system.xml  5
		$a_80_4 = {24 5f 2e 45 78 63 65 70 74 69 6f 6e 2e 4d 65 73 73 61 67 65 20 7c 20 4f 75 74 2d 46 69 6c 65 20 2d 46 69 6c 65 50 61 74 68 20 27 } //$_.Exception.Message | Out-File -FilePath '  2
		$a_80_5 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 20 22 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 } //powershell.exe -WindowStyle Hidden -Command "Start-Process '  1
		$a_80_6 = {64 6f 77 6e 6c 6f 61 64 5f 6c 6f 67 2e 74 78 74 } //download_log.txt  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*5+(#a_80_3  & 1)*5+(#a_80_4  & 1)*2+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=34
 
}