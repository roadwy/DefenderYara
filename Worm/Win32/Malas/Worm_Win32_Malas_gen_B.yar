
rule Worm_Win32_Malas_gen_B{
	meta:
		description = "Worm:Win32/Malas.gen!B,SIGNATURE_TYPE_PEHSTR,06 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 66 77 61 74 63 68 2e 70 64 62 } //01 00  ufwatch.pdb
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 20 53 68 61 72 65 64 5c 44 41 4f 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  Microsoft Shared\DAO\svchost.exe
		$a_01_2 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 44 65 66 61 75 6c 74 3d 31 } //01 00  shell\open\Default=1
		$a_01_3 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 3d 65 78 70 6c 6f 72 65 72 28 26 58 29 } //01 00  shell\explore=explorer(&X)
		$a_01_4 = {5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 20 00 2d 00 6b 00 20 00 6e 00 65 00 74 00 73 00 76 00 63 00 73 00 } //01 00  \svchost.exe -k netsvcs
		$a_01_5 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //00 00  autorun.inf
	condition:
		any of ($a_*)
 
}