
rule Trojan_Win32_Vundo_LR_dll{
	meta:
		description = "Trojan:Win32/Vundo.LR!dll,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 78 69 62 6e 78 77 00 4c 74 6e 6b 72 00 51 6e 77 75 62 77 79 00 } //01 00 
		$a_01_1 = {57 00 75 00 77 00 65 00 69 00 2e 00 64 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}