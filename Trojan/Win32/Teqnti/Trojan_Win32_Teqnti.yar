
rule Trojan_Win32_Teqnti{
	meta:
		description = "Trojan:Win32/Teqnti,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 65 71 75 69 6c 61 62 6f 6f 6d 62 6f 6f 6d } //01 00  tequilaboomboom
		$a_01_1 = {6e 74 64 6c 6c 3a 3a 73 74 72 73 74 72 28 74 20 52 31 2c 20 74 20 27 76 6d 77 61 72 65 27 29 } //01 00  ntdll::strstr(t R1, t 'vmware')
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 53 79 73 54 72 61 63 65 72 } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SysTracer
	condition:
		any of ($a_*)
 
}