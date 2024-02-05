
rule Trojan_Win32_Phaetp_F_dha{
	meta:
		description = "Trojan:Win32/Phaetp.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 03 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 68 65 6c 70 65 72 2e 64 6c 6c 00 48 74 74 70 73 49 6e 69 74 } //02 00 
		$a_01_1 = {78 6f 78 6f 2e 6d 79 64 64 6e 73 2e 63 6f 6d } //01 00 
		$a_01_2 = {25 30 31 36 49 36 34 78 25 30 38 78 00 } //00 00 
	condition:
		any of ($a_*)
 
}