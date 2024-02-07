
rule DDoS_Win32_Nitol_J{
	meta:
		description = "DDoS:Win32/Nitol.J,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 64 2e 25 64 2e 25 64 2e 25 64 00 } //02 00 
		$a_01_1 = {44 4e 53 46 6c 6f 6f 64 } //01 00  DNSFlood
		$a_01_2 = {31 39 32 2e 31 36 38 2e 31 2e 32 34 34 } //02 00  192.168.1.244
		$a_01_3 = {6a 64 66 77 6b 65 79 } //02 00  jdfwkey
		$a_01_4 = {83 c0 03 33 d2 0f af c6 f7 74 24 } //03 00 
		$a_01_5 = {64 64 6f 73 2e 68 61 63 6b 78 6b 2e 63 6f 6d } //00 00  ddos.hackxk.com
		$a_00_6 = {80 10 00 00 ee 79 } //0e 4a 
	condition:
		any of ($a_*)
 
}