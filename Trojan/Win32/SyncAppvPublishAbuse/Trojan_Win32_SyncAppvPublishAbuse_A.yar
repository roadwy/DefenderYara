
rule Trojan_Win32_SyncAppvPublishAbuse_A{
	meta:
		description = "Trojan:Win32/SyncAppvPublishAbuse.A,SIGNATURE_TYPE_CMDHSTR_EXT,0d 00 0d 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {41 00 70 00 70 00 76 00 50 00 75 00 62 00 6c 00 69 00 73 00 68 00 69 00 6e 00 67 00 53 00 65 00 72 00 76 00 65 00 72 00 } //02 00  AppvPublishingServer
		$a_00_1 = {29 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 } //02 00  ).DownloadString(
		$a_00_2 = {29 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 } //01 00  ).DownloadFile(
		$a_00_3 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //01 00  Invoke-Command
		$a_00_4 = {3b 00 49 00 45 00 58 00 } //01 00  ;IEX
		$a_00_5 = {7c 00 49 00 45 00 58 00 } //01 00  |IEX
		$a_00_6 = {20 00 49 00 45 00 58 00 } //00 00   IEX
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_SyncAppvPublishAbuse_A_2{
	meta:
		description = "Trojan:Win32/SyncAppvPublishAbuse.A,SIGNATURE_TYPE_CMDHSTR_EXT,0d 00 0d 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {41 00 70 00 70 00 76 00 50 00 75 00 62 00 6c 00 69 00 73 00 68 00 69 00 6e 00 67 00 53 00 65 00 72 00 76 00 65 00 72 00 } //02 00  AppvPublishingServer
		$a_00_1 = {3a 00 3a 00 52 00 65 00 61 00 64 00 41 00 6c 00 6c 00 42 00 79 00 74 00 65 00 73 00 28 00 } //02 00  ::ReadAllBytes(
		$a_00_2 = {3a 00 3a 00 52 00 65 00 61 00 64 00 41 00 6c 00 6c 00 54 00 65 00 78 00 74 00 28 00 } //02 00  ::ReadAllText(
		$a_00_3 = {47 00 65 00 74 00 2d 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 20 00 } //01 00  Get-Content 
		$a_00_4 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //01 00  Invoke-Command
		$a_00_5 = {3b 00 49 00 45 00 58 00 } //01 00  ;IEX
		$a_00_6 = {7c 00 49 00 45 00 58 00 } //01 00  |IEX
		$a_00_7 = {20 00 49 00 45 00 58 00 } //00 00   IEX
	condition:
		any of ($a_*)
 
}