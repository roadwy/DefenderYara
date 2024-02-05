
rule Backdoor_Win32_Afcore_I{
	meta:
		description = "Backdoor:Win32/Afcore.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 16 8b ca 33 4c 24 08 03 c1 8b c8 83 e1 0f 42 d3 c8 3b 54 24 04 72 ea } //01 00 
		$a_01_1 = {63 6c 65 61 6e 75 70 00 69 6e 69 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}