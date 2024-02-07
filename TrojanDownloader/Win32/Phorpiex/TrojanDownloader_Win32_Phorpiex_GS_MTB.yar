
rule TrojanDownloader_Win32_Phorpiex_GS_MTB{
	meta:
		description = "TrojanDownloader:Win32/Phorpiex.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 74 6c 64 72 6e 65 74 2e 74 6f 70 2f } //01 00  http://tldrnet.top/
		$a_01_1 = {25 00 74 00 65 00 6d 00 70 00 25 00 } //01 00  %temp%
		$a_01_2 = {41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 4e 00 6f 00 74 00 69 00 66 00 79 00 } //01 00  AntiVirusDisableNotify
		$a_01_3 = {46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 4e 00 6f 00 74 00 69 00 66 00 79 00 } //00 00  FirewallDisableNotify
	condition:
		any of ($a_*)
 
}