
rule Backdoor_Win32_Rumsoot_A{
	meta:
		description = "Backdoor:Win32/Rumsoot.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_02_0 = {59 3d 80 51 01 00 7c 05 e8 90 01 02 ff ff e8 90 01 02 ff ff 68 c0 27 09 00 ff 15 90 01 02 00 01 eb 90 04 01 02 c9 ce 90 00 } //01 00 
		$a_00_1 = {75 69 64 3d 25 49 36 34 64 26 67 69 64 3d 25 64 26 63 69 64 3d 25 73 26 72 69 64 3d 25 64 26 73 69 64 3d 25 64 } //01 00  uid=%I64d&gid=%d&cid=%s&rid=%d&sid=%d
		$a_00_2 = {72 75 6e 61 73 73 79 73 75 73 65 72 } //01 00  runassysuser
		$a_00_3 = {77 69 6c 6c 20 72 65 73 75 6c 74 20 69 6e 20 73 79 73 74 65 6d 20 69 6e 73 74 61 62 69 6c 69 74 79 } //01 00  will result in system instability
		$a_00_4 = {5c 70 72 6f 6a 65 63 74 73 5c 63 76 73 5f 70 6f 72 74 5c 70 6f 72 74 5c 74 6f 6f 6c 73 5c 6c 6f 61 64 65 72 5f 6f 75 72 5c 42 69 6e 5c 69 33 38 36 5c 61 5f 6c 6f 61 64 65 72 2e 70 64 62 } //00 00  \projects\cvs_port\port\tools\loader_our\Bin\i386\a_loader.pdb
	condition:
		any of ($a_*)
 
}