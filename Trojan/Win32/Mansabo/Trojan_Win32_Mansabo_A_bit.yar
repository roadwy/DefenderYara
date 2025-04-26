
rule Trojan_Win32_Mansabo_A_bit{
	meta:
		description = "Trojan:Win32/Mansabo.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 63 20 63 72 65 61 74 65 20 66 6f 75 6e 64 61 74 69 6f 6e } //1 sc create foundation
		$a_01_1 = {6b 65 72 6e 65 6c 33 32 3a 3a 49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 28 29 69 2e 52 30 } //1 kernel32::IsDebuggerPresent()i.R0
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}