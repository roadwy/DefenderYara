
rule Trojan_Win32_SelfDel_TB_MTB{
	meta:
		description = "Trojan:Win32/SelfDel.TB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b ce 83 c1 60 81 f1 90 01 04 83 c1 16 2b ce 89 4d c8 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00 
		$a_01_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_01_3 = {38 63 41 42 35 36 37 35 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}