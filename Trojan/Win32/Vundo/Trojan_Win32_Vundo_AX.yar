
rule Trojan_Win32_Vundo_AX{
	meta:
		description = "Trojan:Win32/Vundo.AX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 c6 15 c8 75 } //01 00 
		$a_01_1 = {81 f1 28 76 58 2b } //01 00 
		$a_01_2 = {b9 15 07 91 45 } //01 00 
		$a_01_3 = {81 f1 4f 68 4f ec } //00 00 
	condition:
		any of ($a_*)
 
}