
rule Ransom_Win32_MegaCortex_A{
	meta:
		description = "Ransom:Win32/MegaCortex.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {4d 33 47 41 2d 53 31 3d } //05 00  M3GA-S1=
		$a_01_1 = {21 00 2d 00 21 00 5f 00 52 00 45 00 41 00 44 00 4d 00 45 00 5f 00 21 00 2d 00 21 00 2e 00 72 00 74 00 66 00 } //02 00  !-!_README_!-!.rtf
		$a_01_2 = {43 3a 5c 6d 6f 75 5f 6a 76 73 6f 53 31 2e 6c 6f 67 } //02 00  C:\mou_jvsoS1.log
		$a_01_3 = {63 00 61 00 6c 00 6c 00 20 00 6d 00 6f 00 75 00 5f 00 6a 00 76 00 73 00 6f 00 53 00 31 00 2d 00 32 00 2e 00 63 00 6d 00 64 00 20 00 25 00 31 00 25 00 20 00 63 00 69 00 70 00 68 00 65 00 72 00 20 00 77 00 6d 00 69 00 63 00 } //00 00  call mou_jvsoS1-2.cmd %1% cipher wmic
		$a_00_4 = {7e 15 00 00 81 } //da 92 
	condition:
		any of ($a_*)
 
}