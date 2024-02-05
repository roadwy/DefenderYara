
rule PWS_Win32_Yupfil_A{
	meta:
		description = "PWS:Win32/Yupfil.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 46 10 00 10 00 00 89 5e 18 89 5e 1c 66 89 5e 20 66 89 5e 22 c7 46 24 40 00 00 c0 } //01 00 
		$a_00_1 = {6c 6c 7a 68 75 63 65 62 61 6f 00 } //00 00 
	condition:
		any of ($a_*)
 
}