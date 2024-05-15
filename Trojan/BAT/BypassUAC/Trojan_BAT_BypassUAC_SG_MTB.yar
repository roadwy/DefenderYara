
rule Trojan_BAT_BypassUAC_SG_MTB{
	meta:
		description = "Trojan:BAT/BypassUAC.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 62 61 64 64 6f 6e 53 74 75 62 2e 65 78 65 } //01 00  AbaddonStub.exe
		$a_01_1 = {48 00 54 00 54 00 50 00 44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 } //01 00  HTTPDebuggerBrowser.dll
		$a_01_2 = {2f 00 72 00 75 00 6e 00 20 00 2f 00 74 00 6e 00 20 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 44 00 69 00 73 00 6b 00 43 00 6c 00 65 00 61 00 6e 00 75 00 70 00 5c 00 53 00 69 00 6c 00 65 00 6e 00 74 00 43 00 6c 00 65 00 61 00 6e 00 75 00 70 00 20 00 2f 00 49 00 } //00 00  /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
	condition:
		any of ($a_*)
 
}