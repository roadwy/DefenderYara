
rule Trojan_Win32_CryptInject_DT_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 72 79 79 74 41 46 72 73 74 64 74 79 66 5e 57 54 55 77 } //01 00  tryytAFrstdtyf^WTUw
		$a_01_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_3 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //00 00  QueryPerformanceCounter
	condition:
		any of ($a_*)
 
}