
rule Trojan_Win32_Sumber_A_dha{
	meta:
		description = "Trojan:Win32/Sumber.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {53 4d 42 5f 46 4f 52 5f 41 4c 4c 5f 55 6c 74 69 6d 61 74 65 } //02 00  SMB_FOR_ALL_Ultimate
		$a_01_1 = {43 6f 6d 6d 61 6e 64 20 66 6f 72 6d 61 74 20 20 25 73 20 54 61 72 67 65 74 49 70 20 64 6f 6d 61 69 6e 6e 61 6d 65 } //01 00  Command format  %s TargetIp domainname
		$a_01_2 = {43 6f 6e 73 74 72 75 63 74 20 43 6f 6e 73 54 72 61 6e 73 53 65 63 6f 6e 64 61 72 79 } //01 00  Construct ConsTransSecondary
		$a_01_3 = {63 72 65 61 74 65 20 70 69 70 65 20 74 77 69 63 65 20 66 61 69 6c 65 64 2e } //01 00  create pipe twice failed.
		$a_01_4 = {43 6f 6e 73 74 72 75 63 74 20 4e 54 43 72 65 61 74 65 41 6e 64 58 52 65 71 75 65 73 74 20 20 46 61 69 6c 65 64 2e } //00 00  Construct NTCreateAndXRequest  Failed.
	condition:
		any of ($a_*)
 
}