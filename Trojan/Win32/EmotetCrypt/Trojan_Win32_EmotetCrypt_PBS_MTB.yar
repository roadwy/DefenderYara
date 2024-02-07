
rule Trojan_Win32_EmotetCrypt_PBS_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {45 54 31 51 39 36 72 6c 42 41 41 41 42 76 58 64 68 5a 65 49 35 52 54 2e 70 64 62 } //01 00  ET1Q96rlBAAABvXdhZeI5RT.pdb
		$a_81_1 = {4e 35 66 47 30 6c 78 72 35 7a 6e 75 48 66 38 78 47 57 75 6c 62 47 5f 36 } //01 00  N5fG0lxr5znuHf8xGWulbG_6
		$a_81_2 = {43 72 65 61 74 65 4d 75 74 65 78 57 } //00 00  CreateMutexW
	condition:
		any of ($a_*)
 
}