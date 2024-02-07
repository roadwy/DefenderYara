
rule PWS_Win32_Savnut_F{
	meta:
		description = "PWS:Win32/Savnut.F,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {81 7f 01 74 74 70 73 0f 85 90 01 01 00 00 00 80 7f 08 41 0f 82 90 01 01 00 00 00 81 3d c0 0c 25 00 44 45 55 5f 75 90 00 } //01 00 
		$a_01_1 = {5c 73 72 76 62 6c 63 6b 32 2e 74 6d 70 } //01 00  \srvblck2.tmp
		$a_01_2 = {62 61 6e 6b 63 68 61 6e 67 65 68 6f 73 74 3a } //01 00  bankchangehost:
		$a_01_3 = {5c 75 72 68 74 70 73 2e 64 61 74 } //01 00  \urhtps.dat
		$a_01_4 = {25 73 5c 25 73 5f 25 30 38 64 2e 6d 70 73 74 } //00 00  %s\%s_%08d.mpst
	condition:
		any of ($a_*)
 
}