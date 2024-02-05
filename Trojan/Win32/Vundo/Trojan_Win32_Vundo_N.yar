
rule Trojan_Win32_Vundo_N{
	meta:
		description = "Trojan:Win32/Vundo.N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 0f 00 00 00 68 9c c8 9e da } //01 00 
		$a_01_1 = {68 07 00 00 00 68 34 55 6c cc } //01 00 
		$a_01_2 = {e8 00 00 00 00 68 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}