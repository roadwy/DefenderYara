
rule Trojan_Win32_Qhost_FM{
	meta:
		description = "Trojan:Win32/Qhost.FM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 66 20 2f 69 6d } //01 00 
		$a_00_1 = {39 00 31 00 2e 00 32 00 31 00 37 00 2e 00 31 00 35 00 33 00 2e 00 32 00 30 00 30 00 } //01 00 
		$a_00_2 = {42 00 61 00 74 00 4c 00 6e 00 6b 00 2e 00 6c 00 6e 00 6b 00 } //01 00 
		$a_01_3 = {61 74 74 72 69 62 20 2b 53 20 2b 48 20 2b 52 } //00 00 
	condition:
		any of ($a_*)
 
}