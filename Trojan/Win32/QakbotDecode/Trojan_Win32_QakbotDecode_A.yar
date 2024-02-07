
rule Trojan_Win32_QakbotDecode_A{
	meta:
		description = "Trojan:Win32/QakbotDecode.A,SIGNATURE_TYPE_CMDHSTR_EXT,20 00 20 00 04 00 00 0a 00 "
		
	strings :
		$a_81_0 = {20 2d 64 65 63 6f 64 65 20 } //0a 00   -decode 
		$a_81_1 = {5c 6f 75 74 70 75 74 2e 74 78 74 } //0a 00  \output.txt
		$a_81_2 = {2e 73 71 6c } //02 00  .sql
		$a_81_3 = {63 65 72 74 75 74 69 6c } //00 00  certutil
	condition:
		any of ($a_*)
 
}