
rule Trojan_Win32_QHosts_S{
	meta:
		description = "Trojan:Win32/QHosts.S,SIGNATURE_TYPE_PEHSTR,09 00 09 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 74 00 63 00 5c 00 68 00 6f 00 73 00 74 00 73 00 } //03 00  \system32\drivers\etc\hosts
		$a_01_1 = {43 00 3a 00 5c 00 69 00 6e 00 6f 00 6e 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //02 00  C:\inon\Project1.vbp
		$a_01_2 = {77 00 77 00 77 00 2e 00 62 00 61 00 6e 00 63 00 6f 00 6d 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 } //02 00  www.bancomer.com
		$a_01_3 = {77 00 77 00 77 00 2e 00 62 00 62 00 76 00 61 00 2e 00 63 00 6f 00 6d 00 2e 00 6d 00 78 00 } //00 00  www.bbva.com.mx
	condition:
		any of ($a_*)
 
}