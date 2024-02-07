
rule Trojan_Win32_Qhost_DW{
	meta:
		description = "Trojan:Win32/Qhost.DW,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 34 11 19 03 ca 42 3b d0 7c f2 } //01 00 
		$a_03_1 = {6c 6c 33 32 c7 45 90 01 01 2e 65 78 65 c7 45 90 01 01 20 73 65 74 c7 45 90 01 01 75 70 61 70 90 00 } //01 00 
		$a_03_2 = {c1 ee 1b c1 90 01 01 05 0b 90 01 01 0f 90 01 01 c1 8a 90 01 01 01 03 c6 42 84 c9 75 e9 90 00 } //01 00 
		$a_00_3 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //01 00  \drivers\etc\hosts
		$a_00_4 = {31 32 37 2e 30 2e 30 2e 31 20 64 2e 33 36 30 73 61 66 65 2e 63 6f 6d } //00 00  127.0.0.1 d.360safe.com
	condition:
		any of ($a_*)
 
}