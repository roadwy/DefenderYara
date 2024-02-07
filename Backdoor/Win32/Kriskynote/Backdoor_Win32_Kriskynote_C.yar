
rule Backdoor_Win32_Kriskynote_C{
	meta:
		description = "Backdoor:Win32/Kriskynote.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {b1 99 85 ed 7e 0f 8a 14 18 32 d1 fe c1 88 14 18 40 3b c5 7c f1 8b 4c 24 1c } //01 00 
		$a_01_1 = {41 73 73 65 63 6f 72 50 65 74 61 65 72 43 } //00 00  AssecorPetaerC
	condition:
		any of ($a_*)
 
}