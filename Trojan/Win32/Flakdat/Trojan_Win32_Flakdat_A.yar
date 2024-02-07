
rule Trojan_Win32_Flakdat_A{
	meta:
		description = "Trojan:Win32/Flakdat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {05 c0 03 00 00 3d 00 e0 01 00 75 ed } //01 00 
		$a_01_1 = {52 75 6e 00 5c 00 2e 65 78 65 00 00 00 00 73 79 73 63 6f 6e 66 73 72 76 33 32 } //01 00 
		$a_01_2 = {24 21 52 51 00 00 21 24 00 24 21 52 46 } //01 00 
		$a_01_3 = {5c 66 6b 6c 2e 64 61 74 } //00 00  \fkl.dat
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}