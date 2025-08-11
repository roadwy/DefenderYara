
rule Trojan_Win64_MalDrv_I_MTB{
	meta:
		description = "Trojan:Win64/MalDrv.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {44 72 69 76 65 72 45 6e 74 72 79 20 66 61 69 6c 65 64 20 30 78 25 78 20 66 6f 72 20 64 72 69 76 65 72 20 25 77 } //1 DriverEntry failed 0x%x for driver %w
		$a_01_1 = {5c 52 65 6c 65 61 73 65 5c 44 44 72 69 76 65 72 2e 70 64 62 } //1 \Release\DDriver.pdb
		$a_01_2 = {4d 70 43 6d 64 52 75 6e 2e 65 78 65 } //1 MpCmdRun.exe
		$a_01_3 = {53 6d 61 72 74 53 63 72 65 65 6e 2e 65 78 65 } //1 SmartScreen.exe
		$a_01_4 = {53 65 63 75 72 69 74 79 48 65 61 6c 74 68 53 79 73 74 72 61 79 2e 65 78 65 } //1 SecurityHealthSystray.exe
		$a_01_5 = {53 65 63 75 72 69 74 79 48 65 61 6c 74 68 48 6f 73 74 2e 65 78 65 } //1 SecurityHealthHost.exe
		$a_01_6 = {75 68 73 73 76 63 2e 65 78 65 } //1 uhssvc.exe
		$a_01_7 = {4d 73 4d 70 45 6e 67 2e 65 78 65 } //1 MsMpEng.exe
		$a_01_8 = {4d 70 44 65 66 65 6e 64 65 72 43 6f 72 65 53 65 72 76 69 63 65 2e 65 78 65 } //1 MpDefenderCoreService.exe
		$a_01_9 = {4e 69 73 53 72 76 2e 65 78 65 } //1 NisSrv.exe
		$a_01_10 = {4d 73 53 65 6e 73 65 2e 65 78 65 } //1 MsSense.exe
		$a_01_11 = {53 67 72 6d 42 72 6f 6b 65 72 2e 65 78 65 } //1 SgrmBroker.exe
		$a_01_12 = {53 65 63 75 72 69 74 79 48 65 61 6c 74 68 53 65 72 76 69 63 65 2e 65 78 65 } //1 SecurityHealthService.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}