
rule TrojanDownloader_Win32_Agent_EF_dll{
	meta:
		description = "TrojanDownloader:Win32/Agent.EF!dll,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 65 72 76 69 63 65 4d 61 69 6e } //1 ServiceMain
		$a_01_1 = {47 6c 6f 62 61 6c 5c 49 50 52 49 50 } //1 Global\IPRIP
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 Applications\iexplore.exe\shell\open\command
		$a_01_3 = {5c 73 76 63 68 6f 73 74 2e 64 6c 6c } //1 \svchost.dll
		$a_01_4 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c } //1 SYSTEM\CurrentControlSet\Services\
		$a_01_5 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //1 SeDebugPrivilege
		$a_01_6 = {43 56 69 64 65 6f 43 61 70 } //1 CVideoCap
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}