
rule Trojan_Win32_Nabucur_AA{
	meta:
		description = "Trojan:Win32/Nabucur.AA,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 00 68 05 30 40 00 68 00 30 40 00 6a 00 e8 17 04 00 00 6a 00 e8 16 04 00 00 e8 17 04 00 00 e8 1e 04 00 00 e8 13 04 00 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 } //00 00 
	condition:
		any of ($a_*)
 
}