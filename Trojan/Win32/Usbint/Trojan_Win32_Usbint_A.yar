
rule Trojan_Win32_Usbint_A{
	meta:
		description = "Trojan:Win32/Usbint.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //01 00  KeServiceDescriptorTable
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 54 45 4e 43 45 4e 54 5c 50 4c 41 54 46 4f 52 4d 5f 54 59 50 45 5f 4c 49 53 54 } //01 00  SOFTWARE\TENCENT\PLATFORM_TYPE_LIST
		$a_00_2 = {54 49 4d 50 6c 61 74 66 6f 72 6d 2e 65 78 65 } //01 00  TIMPlatform.exe
		$a_00_3 = {44 72 69 76 65 72 73 5c 75 73 62 69 6e 74 65 2e 73 79 73 } //01 00  Drivers\usbinte.sys
		$a_00_4 = {65 78 65 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00  exefile\shell\open\command
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //00 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
	condition:
		any of ($a_*)
 
}