
rule Trojan_Win32_Reconyc_HMP_MTB{
	meta:
		description = "Trojan:Win32/Reconyc.HMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {89 45 d0 be 90 01 04 81 f6 90 01 04 2b 35 90 01 04 83 f6 90 01 01 81 c6 90 01 04 2b 75 90 01 01 33 f0 03 35 90 01 04 89 75 90 00 } //01 00 
		$a_01_1 = {2e 70 6f 6c 79 70 68 61 48 } //01 00 
		$a_01_2 = {2e 64 75 6d 70 73 } //01 00 
		$a_01_3 = {2e 65 72 6f 74 6f 67 65 } //01 00 
		$a_01_4 = {2e 6e 6f 6e 63 61 74 65 } //01 00 
		$a_01_5 = {2e 66 69 6e 6b 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}