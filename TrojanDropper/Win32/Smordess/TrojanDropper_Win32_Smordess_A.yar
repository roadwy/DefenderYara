
rule TrojanDropper_Win32_Smordess_A{
	meta:
		description = "TrojanDropper:Win32/Smordess.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f a2 0f 31 4e 75 f9 } //01 00 
		$a_01_1 = {69 67 66 78 65 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}