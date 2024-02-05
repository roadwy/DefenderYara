
rule PWS_Win32_Witkinat_A{
	meta:
		description = "PWS:Win32/Witkinat.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 60 ea 00 00 73 90 01 01 68 ff 7f 00 00 b9 90 01 04 8d 85 00 80 fd ff ba ff ff 00 00 e8 90 00 } //01 00 
		$a_03_1 = {ba 00 00 01 00 e8 90 01 04 68 90 01 04 68 90 01 04 e8 90 01 04 6a 00 68 82 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 85 f3 7f fe ff 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}