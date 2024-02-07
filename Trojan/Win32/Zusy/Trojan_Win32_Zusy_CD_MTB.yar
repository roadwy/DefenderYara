
rule Trojan_Win32_Zusy_CD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 43 78 66 65 7a 5a 6a 69 50 62 2e 64 6c 6c } //01 00  FCxfezZjiPb.dll
		$a_01_1 = {67 63 43 4d 45 42 52 75 67 2e 64 6c 6c } //01 00  gcCMEBRug.dll
		$a_01_2 = {40 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 53 00 79 00 6e 00 63 00 52 00 6f 00 6f 00 74 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //01 00  @Software\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager
		$a_01_3 = {46 00 69 00 72 00 73 00 74 00 52 00 75 00 6e 00 } //01 00  FirstRun
		$a_01_4 = {79 74 68 64 43 64 70 68 44 7a 66 2e 64 6c 6c } //01 00  ythdCdphDzf.dll
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}