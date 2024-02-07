
rule Ransom_Win32_Roclis{
	meta:
		description = "Ransom:Win32/Roclis,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 04 00 "
		
	strings :
		$a_01_0 = {40 5f 52 45 53 54 4f 52 45 2d 46 49 4c 45 53 5f 40 2e 74 78 74 } //04 00  @_RESTORE-FILES_@.txt
		$a_01_1 = {21 2d 47 45 54 5f 4d 59 5f 46 49 4c 45 53 2d 21 2e 74 78 74 } //04 00  !-GET_MY_FILES-!.txt
		$a_01_2 = {23 52 45 43 4f 56 45 52 59 2d 50 43 23 2e 74 78 74 } //08 00  #RECOVERY-PC#.txt
		$a_01_3 = {5a 3a 5c 73 74 6f 70 5c 73 6f 72 63 65 73 5c 41 75 72 6f 72 61 5c 6f 6c 64 5f 73 6f 72 63 5c 44 65 62 75 67 5c 52 61 6e 73 6f 6d 2e 70 64 62 } //00 00  Z:\stop\sorces\Aurora\old_sorc\Debug\Ransom.pdb
		$a_00_4 = {5d 04 00 00 ef c4 03 80 5c 25 00 00 } //f0 c4 
	condition:
		any of ($a_*)
 
}