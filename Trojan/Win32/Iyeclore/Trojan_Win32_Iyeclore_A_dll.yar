
rule Trojan_Win32_Iyeclore_A_dll{
	meta:
		description = "Trojan:Win32/Iyeclore.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 73 73 74 67 67 66 2e 64 6c 6c 00 53 79 73 74 65 6d 52 65 67 69 73 74 65 72 00 } //01 00 
		$a_01_1 = {4d 73 73 72 62 64 74 2e 64 6c 6c 00 53 79 73 74 65 6d 52 65 67 69 73 74 65 72 00 } //0a 00 
		$a_01_2 = {d5 d2 b2 bb b5 bd b7 fe ce f1 c6 f7 00 } //0a 00 
		$a_01_3 = {4d 61 78 74 68 6f 6e 00 } //0a 00  慍瑸潨n
		$a_01_4 = {54 65 6e 63 65 6e 74 20 54 72 61 76 65 6c 65 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}