
rule Trojan_Win32_SuspServiceStop_A{
	meta:
		description = "Trojan:Win32/SuspServiceStop.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 2e 00 65 00 78 00 65 00 20 00 73 00 74 00 6f 00 70 00 } //02 00  sc.exe stop
		$a_00_1 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 20 00 73 00 74 00 6f 00 70 00 } //02 00  net.exe stop
		$a_00_2 = {73 00 63 00 20 00 73 00 74 00 6f 00 70 00 } //02 00  sc stop
		$a_00_3 = {6e 00 65 00 74 00 20 00 73 00 74 00 6f 00 70 00 } //00 00  net stop
	condition:
		any of ($a_*)
 
}