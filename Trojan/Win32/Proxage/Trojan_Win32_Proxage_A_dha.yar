
rule Trojan_Win32_Proxage_A_dha{
	meta:
		description = "Trojan:Win32/Proxage.A!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 69 72 61 67 65 46 6f 78 } //01 00 
		$a_01_1 = {2e 6d 65 63 68 61 6e 69 63 6e 6f 74 65 2e 63 6f 6d } //01 00 
		$a_01_2 = {2f 73 65 61 72 63 68 3f 67 69 64 3d 25 73 } //01 00 
		$a_01_3 = {2f 63 20 64 65 6c 20 25 73 20 3e 20 6e 75 6c } //00 00 
		$a_01_4 = {00 5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}