
rule Trojan_Win32_Farfli_MM_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_81_0 = {63 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 4e 54 5f 50 61 74 68 2e 67 69 66 } //01 00  c:\Program Files\NT_Path.gif
		$a_81_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74 } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\SvcHost
		$a_81_2 = {4d 58 49 41 4e 47 } //01 00  MXIANG
		$a_81_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 52 65 6d 6f 74 65 41 63 63 65 73 73 5c 52 6f 75 74 65 72 4d 61 6e 61 67 65 72 73 5c 49 70 } //01 00  SYSTEM\CurrentControlSet\Services\RemoteAccess\RouterManagers\Ip
		$a_81_4 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 5c 57 64 73 5c 72 64 70 77 64 5c 54 64 73 5c 74 63 70 } //01 00  SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\Tds\tcp
		$a_81_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //01 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_81_6 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00  CallNextHookEx
		$a_81_7 = {53 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //01 00  SetClipboardData
		$a_81_8 = {53 6c 65 65 70 } //01 00  Sleep
		$a_81_9 = {47 65 74 4b 65 79 4e 61 6d 65 54 65 78 74 41 } //01 00  GetKeyNameTextA
		$a_81_10 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //01 00  FindResourceA
		$a_81_11 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //01 00  SizeofResource
		$a_81_12 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //01 00  LoadResource
		$a_81_13 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //00 00  LockResource
	condition:
		any of ($a_*)
 
}