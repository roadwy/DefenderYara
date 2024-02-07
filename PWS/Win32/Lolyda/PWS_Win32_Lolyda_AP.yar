
rule PWS_Win32_Lolyda_AP{
	meta:
		description = "PWS:Win32/Lolyda.AP,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 65 6e 51 51 41 63 63 6f 75 6e 74 2e 64 6c 6c } //01 00  TenQQAccount.dll
		$a_01_1 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 69 6d 61 67 65 2f 70 6a 70 65 67 } //01 00  Content-Type: image/pjpeg
		$a_01_2 = {6e 61 6d 65 3d 22 73 75 62 6d 69 74 74 65 64 22 } //01 00  name="submitted"
		$a_01_3 = {5c 44 4e 46 5c 52 65 6c 65 61 73 65 5c 52 53 44 46 4c 2e 70 64 62 } //01 00  \DNF\Release\RSDFL.pdb
		$a_01_4 = {4d 69 6e 69 53 6e 69 66 66 65 72 } //00 00  MiniSniffer
	condition:
		any of ($a_*)
 
}