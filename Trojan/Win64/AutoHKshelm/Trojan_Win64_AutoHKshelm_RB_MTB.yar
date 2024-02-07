
rule Trojan_Win64_AutoHKshelm_RB_MTB{
	meta:
		description = "Trojan:Win64/AutoHKshelm.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 6d 64 2e 65 78 65 20 2f 63 20 50 4f 57 65 52 53 48 65 4c 4c 2e 65 58 65 20 2d 4e 4f 50 20 2d 57 49 4e 44 20 48 49 44 44 65 4e 20 2d 65 58 65 43 20 42 59 50 41 53 53 20 2d 4e 4f 4e 49 20 3c 20 4b 65 79 5c 50 65 72 66 4c 6f 67 73 5c 6c 6f 67 6f 2e 6a 70 67 20 20 2c 2c 68 69 64 65 } //01 00  Cmd.exe /c POWeRSHeLL.eXe -NOP -WIND HIDDeN -eXeC BYPASS -NONI < Key\PerfLogs\logo.jpg  ,,hide
		$a_81_1 = {43 6d 64 2e 65 78 65 20 2f 63 20 50 4f 57 65 52 53 48 65 4c 4c 2e 65 58 65 20 2d 4e 4f 50 20 2d 57 49 4e 44 20 48 49 44 44 65 4e 20 2d 65 58 65 43 20 42 59 50 41 53 53 20 2d 4e 4f 4e 49 20 3c 20 4b 65 79 5c 50 65 72 66 4c 6f 67 73 5c 45 6e 74 65 72 70 72 69 73 65 41 70 70 4d 67 6d 74 53 76 63 2e 6a 70 67 } //01 00  Cmd.exe /c POWeRSHeLL.eXe -NOP -WIND HIDDeN -eXeC BYPASS -NONI < Key\PerfLogs\EnterpriseAppMgmtSvc.jpg
		$a_81_2 = {43 6d 64 2e 65 78 65 20 2f 63 20 50 4f 57 65 52 53 48 65 4c 4c 2e 65 58 65 20 2d 4e 4f 50 20 2d 57 49 4e 44 20 48 49 44 44 65 4e 20 2d 65 58 65 43 20 42 59 50 41 53 53 20 2d 4e 4f 4e 49 20 3c 20 4b 65 79 5c 50 65 72 66 4c 6f 67 73 5c 41 70 70 58 44 65 70 6c 6f 79 6d 65 6e 74 53 65 72 76 65 72 2e 6a 70 67 } //01 00  Cmd.exe /c POWeRSHeLL.eXe -NOP -WIND HIDDeN -eXeC BYPASS -NONI < Key\PerfLogs\AppXDeploymentServer.jpg
		$a_81_3 = {4b 65 79 5c 65 6e 2d 55 53 5c 46 6f 6e 74 73 5c 31 2e 65 78 65 } //01 00  Key\en-US\Fonts\1.exe
		$a_81_4 = {25 41 70 70 44 61 74 61 25 5c 50 65 72 66 4c 6f 67 73 5c 4b 65 79 2e 76 62 73 } //01 00  %AppData%\PerfLogs\Key.vbs
		$a_81_5 = {46 69 6c 65 45 78 69 73 74 28 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 41 76 69 72 61 5c 22 29 } //01 00  FileExist("C:\ProgramData\Avira\")
		$a_81_6 = {46 69 6c 65 52 65 6d 6f 76 65 44 69 72 2c 20 25 41 70 70 44 61 74 61 25 5c 50 65 72 66 4c 6f 67 73 5c 50 65 72 66 4c 6f 67 73 2c 20 31 } //00 00  FileRemoveDir, %AppData%\PerfLogs\PerfLogs, 1
	condition:
		any of ($a_*)
 
}