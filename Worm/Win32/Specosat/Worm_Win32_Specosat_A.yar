
rule Worm_Win32_Specosat_A{
	meta:
		description = "Worm:Win32/Specosat.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 48 6f 73 74 73 52 65 73 70 6f 6e 73 65 26 64 61 74 61 3d } //01 00  =HostsResponse&data=
		$a_01_1 = {3d 53 79 73 74 65 6d 49 6e 66 6f 52 65 73 70 6f 6e 73 65 26 64 61 74 61 3d 4f 53 3a } //01 00  =SystemInfoResponse&data=OS:
		$a_01_2 = {25 63 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 25 63 3a 5c 25 } //01 00 
		$a_01_3 = {3d 4b 65 79 6c 6f 67 52 65 73 70 6f 6e 73 65 26 64 61 74 61 3d } //01 00  =KeylogResponse&data=
		$a_01_4 = {73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 52 55 20 22 25 73 22 20 2f 53 43 20 4d 49 4e 55 54 45 20 2f 54 52 } //01 00  schtasks /Create /RU "%s" /SC MINUTE /TR
		$a_01_5 = {3d 49 41 6d 41 6c 69 76 65 00 } //01 00  䤽流汁癩e
		$a_01_6 = {2e 44 6f 77 6e 45 78 65 63 46 69 6c 65 2d 3e } //00 00  .DownExecFile->
	condition:
		any of ($a_*)
 
}