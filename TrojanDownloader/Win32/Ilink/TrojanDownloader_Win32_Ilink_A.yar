
rule TrojanDownloader_Win32_Ilink_A{
	meta:
		description = "TrojanDownloader:Win32/Ilink.A,SIGNATURE_TYPE_PEHSTR,36 00 36 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //0a 00  SOFTWARE\Microsoft\Windows\CurrentVersion
		$a_01_1 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 5c } //0a 00  SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List\
		$a_01_2 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a } //0a 00  :*:Enabled:
		$a_01_3 = {75 73 65 20 4d 53 49 4c 20 63 6f 64 65 20 66 72 6f 6d 20 74 68 69 73 } //0a 00  use MSIL code from this
		$a_01_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_5 = {66 72 6c 69 6e 6b 2e 69 6e } //01 00  frlink.in
		$a_01_6 = {00 25 75 2e 25 75 00 } //01 00 
		$a_01_7 = {00 2e 70 68 70 00 } //01 00  ⸀桰p
		$a_01_8 = {00 3f 69 64 3d 00 } //01 00  㼀摩=
		$a_01_9 = {00 26 6f 73 3d 00 } //00 00  ☀獯=
	condition:
		any of ($a_*)
 
}