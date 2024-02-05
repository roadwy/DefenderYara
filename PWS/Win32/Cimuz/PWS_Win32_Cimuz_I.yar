
rule PWS_Win32_Cimuz_I{
	meta:
		description = "PWS:Win32/Cimuz.I,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {76 10 8b c1 6a 05 99 90 01 01 f7 90 01 01 30 14 90 01 01 41 3b 90 01 01 72 f0 8b 35 90 01 09 bd 90 01 05 55 ff d6 90 01 01 e8 90 01 02 ff ff 90 00 } //01 00 
		$a_01_1 = {3d c5 f8 ae ca } //01 00 
		$a_01_2 = {52 54 5f 52 45 47 44 4c 4c 00 } //01 00 
		$a_01_3 = {52 54 5f 44 4c 4c 00 } //00 00 
	condition:
		any of ($a_*)
 
}