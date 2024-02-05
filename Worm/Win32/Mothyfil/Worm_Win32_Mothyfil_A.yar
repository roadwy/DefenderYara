
rule Worm_Win32_Mothyfil_A{
	meta:
		description = "Worm:Win32/Mothyfil.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 75 63 6b 5f 75 34 00 66 75 63 6b 5f 75 35 00 43 6c 61 73 73 31 00 00 50 72 6f 6a 65 63 74 31 00 } //00 00 
	condition:
		any of ($a_*)
 
}