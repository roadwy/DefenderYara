
rule Trojan_Win32_PplProcAttackTool{
	meta:
		description = "Trojan:Win32/PplProcAttackTool,SIGNATURE_TYPE_PEHSTR,ffffffd7 00 ffffffd7 00 21 00 00 "
		
	strings :
		$a_01_0 = {2f 50 50 4c 42 6c 61 64 65 2f 64 72 69 76 65 72 2e 67 6f } //25 /PPLBlade/driver.go
		$a_01_1 = {2f 50 50 4c 42 6c 61 64 65 2f 68 61 6e 64 6c 65 5f 6f 70 65 6e 65 72 73 2e 67 6f } //25 /PPLBlade/handle_openers.go
		$a_01_2 = {2f 50 50 4c 42 6c 61 64 65 2f 68 6f 75 73 65 6b 65 65 70 69 6e 67 2e 67 6f } //25 /PPLBlade/housekeeping.go
		$a_01_3 = {2f 50 50 4c 42 6c 61 64 65 2f 70 72 6f 63 65 73 73 5f 61 63 74 69 6f 6e 5f 68 65 6c 70 65 72 73 2e 67 6f } //25 /PPLBlade/process_action_helpers.go
		$a_01_4 = {2f 50 50 4c 42 6c 61 64 65 2f 70 72 69 76 69 6c 6c 65 67 65 73 2e 67 6f } //25 /PPLBlade/privilleges.go
		$a_01_5 = {2f 50 50 4c 42 6c 61 64 65 2f 70 72 6f 63 65 73 73 5f 61 63 74 69 6f 6e 73 2e 67 6f } //25 /PPLBlade/process_actions.go
		$a_01_6 = {2f 50 50 4c 42 6c 61 64 65 2f 73 65 72 76 69 63 65 2e 67 6f } //25 /PPLBlade/service.go
		$a_01_7 = {2f 50 50 4c 42 6c 61 64 65 2f 74 6f 6f 6c 73 2e 67 6f } //25 /PPLBlade/tools.go
		$a_01_8 = {6d 61 69 6e 2e 47 65 74 50 72 6f 63 45 78 70 44 72 69 76 65 72 } //1 main.GetProcExpDriver
		$a_01_9 = {6d 61 69 6e 2e 44 72 69 76 65 72 4f 70 65 6e 50 72 6f 63 65 73 73 } //1 main.DriverOpenProcess
		$a_01_10 = {6d 61 69 6e 2e 57 72 69 74 65 44 72 69 76 65 72 4f 6e 44 69 73 6b } //1 main.WriteDriverOnDisk
		$a_01_11 = {6d 61 69 6e 2e 4f 70 65 6e 50 72 6f 63 65 73 73 48 61 6e 64 6c 65 } //1 main.OpenProcessHandle
		$a_01_12 = {6d 61 69 6e 2e 44 69 72 65 63 74 4f 70 65 6e 50 72 6f 63 } //1 main.DirectOpenProc
		$a_01_13 = {6d 61 69 6e 2e 50 72 6f 63 45 78 70 4f 70 65 6e 50 72 6f 63 } //1 main.ProcExpOpenProc
		$a_01_14 = {6d 61 69 6e 2e 53 65 74 55 70 44 72 69 76 65 72 4d 6f 64 65 } //1 main.SetUpDriverMode
		$a_01_15 = {6d 61 69 6e 2e 6d 69 6e 69 44 75 6d 70 43 61 6c 6c 62 61 63 6b } //1 main.miniDumpCallback
		$a_01_16 = {6d 61 69 6e 2e 70 74 72 54 6f 4d 69 6e 69 64 75 6d 70 43 61 6c 6c 62 61 63 6b 49 6e 70 75 74 } //1 main.ptrToMinidumpCallbackInput
		$a_01_17 = {6d 61 69 6e 2e 70 74 72 54 6f 4d 69 6e 69 64 75 6d 70 43 61 6c 6c 62 61 63 6b 4f 75 74 70 75 74 } //1 main.ptrToMinidumpCallbackOutput
		$a_01_18 = {6d 61 69 6e 2e 73 65 74 4e 65 77 43 61 6c 6c 62 61 63 6b 4f 75 74 70 75 74 } //1 main.setNewCallbackOutput
		$a_01_19 = {6d 61 69 6e 2e 63 6f 70 79 44 75 6d 70 42 79 74 65 73 } //1 main.copyDumpBytes
		$a_01_20 = {6d 61 69 6e 2e 4d 69 6e 69 44 75 6d 70 47 65 74 42 79 74 65 73 } //1 main.MiniDumpGetBytes
		$a_01_21 = {6d 61 69 6e 2e 53 65 6e 64 42 79 74 65 73 52 61 77 } //1 main.SendBytesRaw
		$a_01_22 = {6d 61 69 6e 2e 53 65 6e 64 42 79 74 65 73 53 4d 42 } //1 main.SendBytesSMB
		$a_01_23 = {6d 61 69 6e 2e 44 65 6f 62 66 75 73 63 61 74 65 44 75 6d 70 } //1 main.DeobfuscateDump
		$a_01_24 = {6d 61 69 6e 2e 43 72 65 61 74 65 53 65 72 76 69 63 65 } //1 main.CreateService
		$a_01_25 = {6d 61 69 6e 2e 56 65 72 69 66 79 53 65 72 76 69 63 65 43 6f 6e 66 69 67 } //1 main.VerifyServiceConfig
		$a_01_26 = {6d 61 69 6e 2e 56 65 72 69 66 79 53 65 72 76 69 63 65 52 75 6e 6e 69 6e 67 } //1 main.VerifyServiceRunning
		$a_01_27 = {6d 61 69 6e 2e 52 65 6d 6f 76 65 53 65 72 76 69 63 65 } //1 main.RemoveService
		$a_01_28 = {6d 61 69 6e 2e 75 70 64 61 74 65 53 69 64 54 79 70 65 49 6d 70 6f 72 74 65 64 } //1 main.updateSidTypeImported
		$a_01_29 = {6d 61 69 6e 2e 75 70 64 61 74 65 53 74 61 72 74 55 70 49 6d 70 6f 72 74 65 64 } //1 main.updateStartUpImported
		$a_01_30 = {6d 61 69 6e 2e 74 6f 53 74 72 69 6e 67 42 6c 6f 63 6b 49 6d 70 6f 72 74 65 64 } //1 main.toStringBlockImported
		$a_01_31 = {6d 61 69 6e 2e 75 70 64 61 74 65 44 65 73 63 72 69 70 74 69 6f 6e 49 6d 70 6f 72 74 65 64 } //1 main.updateDescriptionImported
		$a_01_32 = {6d 61 69 6e 2e 56 61 6c 69 64 61 74 65 41 72 67 75 6d 65 6e 74 73 } //1 main.ValidateArguments
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*25+(#a_01_2  & 1)*25+(#a_01_3  & 1)*25+(#a_01_4  & 1)*25+(#a_01_5  & 1)*25+(#a_01_6  & 1)*25+(#a_01_7  & 1)*25+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1+(#a_01_28  & 1)*1+(#a_01_29  & 1)*1+(#a_01_30  & 1)*1+(#a_01_31  & 1)*1+(#a_01_32  & 1)*1) >=215
 
}