
rule Trojan_BAT_NjRat_NEAZ_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {24 37 63 62 34 35 66 61 66 2d 37 65 30 66 2d 34 62 37 39 2d 38 33 65 65 2d 65 36 33 31 35 37 36 35 36 39 34 38 } //05 00  $7cb45faf-7e0f-4b79-83ee-e63157656948
		$a_01_1 = {63 3a 5c 75 73 65 72 73 5c 74 65 6f 5c 64 6f 63 75 6d 65 6e 74 73 5c 76 69 73 75 61 6c 20 73 74 75 64 69 6f 20 32 30 31 35 5c 50 72 6f 6a 65 63 74 73 5c 72 6f 73 69 6e 6a 65 63 74 5c 72 6f 73 69 6e 6a 65 63 74 5c 6f 62 6a 5c 44 65 62 75 67 5c 72 6f 73 69 6e 6a 65 63 74 2e 70 64 62 } //05 00  c:\users\teo\documents\visual studio 2015\Projects\rosinject\rosinject\obj\Debug\rosinject.pdb
		$a_01_2 = {72 6f 73 69 6e 6a 65 63 74 2e 65 78 65 } //00 00  rosinject.exe
	condition:
		any of ($a_*)
 
}