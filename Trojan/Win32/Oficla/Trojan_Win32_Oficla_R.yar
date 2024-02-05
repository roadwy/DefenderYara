
rule Trojan_Win32_Oficla_R{
	meta:
		description = "Trojan:Win32/Oficla.R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 7b ff 3f 74 04 c6 03 26 } //01 00 
		$a_01_1 = {30 0c 02 40 83 f8 10 75 f1 83 c2 10 } //00 00 
	condition:
		any of ($a_*)
 
}