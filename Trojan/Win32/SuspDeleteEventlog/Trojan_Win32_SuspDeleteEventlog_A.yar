
rule Trojan_Win32_SuspDeleteEventlog_A{
	meta:
		description = "Trojan:Win32/SuspDeleteEventlog.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 08 00 00 02 00 "
		
	strings :
		$a_00_0 = {77 00 65 00 76 00 74 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 63 00 6c 00 20 00 } //02 00  wevtutil.exe cl 
		$a_00_1 = {77 00 65 00 76 00 74 00 75 00 74 00 69 00 6c 00 20 00 63 00 6c 00 20 00 } //02 00  wevtutil cl 
		$a_02_2 = {77 00 65 00 76 00 74 00 75 00 74 00 69 00 6c 00 90 02 50 63 00 6c 00 65 00 61 00 72 00 2d 00 6c 00 6f 00 67 00 90 00 } //f6 ff 
		$a_00_3 = {2f 00 44 00 65 00 62 00 75 00 67 00 } //f6 ff  /Debug
		$a_00_4 = {2f 00 41 00 6e 00 61 00 6c 00 79 00 74 00 69 00 63 00 } //f6 ff  /Analytic
		$a_00_5 = {2f 00 44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 } //f6 ff  /Diagnostic
		$a_00_6 = {2f 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 } //f6 ff  /Operational
		$a_00_7 = {2f 00 54 00 72 00 61 00 63 00 65 00 } //00 00  /Trace
	condition:
		any of ($a_*)
 
}