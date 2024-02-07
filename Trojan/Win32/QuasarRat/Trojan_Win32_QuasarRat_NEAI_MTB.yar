
rule Trojan_Win32_QuasarRat_NEAI_MTB{
	meta:
		description = "Trojan:Win32/QuasarRat.NEAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 70 6f 6f 66 65 72 2e 73 79 74 65 73 2e 6e 65 74 } //02 00  http://spoofer.sytes.net
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 } //02 00  SOFTWARE\Policies\Microsoft\Windows Defender
		$a_01_2 = {52 65 67 69 73 74 79 20 65 6e 74 72 69 65 28 73 29 20 77 65 72 65 20 73 70 6f 6f 66 65 64 2e } //02 00  Registy entrie(s) were spoofed.
		$a_01_3 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //02 00  DisableAntiSpyware
		$a_01_4 = {52 65 61 6c 2d 54 69 6d 65 20 50 72 6f 74 65 63 74 69 6f 6e } //02 00  Real-Time Protection
		$a_01_5 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //00 00  DisableRealtimeMonitoring
	condition:
		any of ($a_*)
 
}