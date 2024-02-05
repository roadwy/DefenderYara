
rule Backdoor_Win32_Talsab_H{
	meta:
		description = "Backdoor:Win32/Talsab.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed } //01 00 
		$a_00_1 = {6e 74 6c 64 72 2e 64 6c 6c 00 00 00 79 6f 6b 6c 61 6d } //00 00 
	condition:
		any of ($a_*)
 
}