
rule PWS_Win32_Dofoil_A{
	meta:
		description = "PWS:Win32/Dofoil.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 6d 6f 64 75 6c 65 3d 67 72 61 62 62 65 72 73 } //01 00 
		$a_03_1 = {f8 50 6a 2f 68 90 01 04 57 90 09 02 00 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}