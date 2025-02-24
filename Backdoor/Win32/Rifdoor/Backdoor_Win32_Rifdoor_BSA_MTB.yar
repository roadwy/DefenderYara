
rule Backdoor_Win32_Rifdoor_BSA_MTB{
	meta:
		description = "Backdoor:Win32/Rifdoor.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 15 98 c1 40 00 85 c0 75 63 8b 17 52 8d 85 e8 fb ff ff 68 b0 e4 40 00 50 ff 15 a0 c1 40 00 83 c4 0c e8 97 fd ff ff 68 c8 e4 40 00 8d 4d e8 51 ff 15 e4 c0 40 00 80 7d e8 00 8d 45 e8 74 0d 8b c8 80 30 0f 41 80 39 00 8b c1 75 f5 6a 00 6a 00 8d 95 e8 fb ff ff 52 8d 45 e8 50 6a 00 6a 00 ff 15 88 c1 40 00 6a 00 } //20
		$a_01_1 = {5c 44 61 74 61 5c 4d 79 20 50 72 6f 6a 65 63 74 73 5c 54 72 6f 79 20 53 6f 75 72 63 65 20 43 6f 64 65 5c 74 63 70 31 73 74 5c 72 69 66 6c 65 5c 52 65 6c 65 61 73 65 5c 72 69 66 6c 65 2e 70 64 62 } //1 \Data\My Projects\Troy Source Code\tcp1st\rifle\Release\rifle.pdb
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*1) >=21
 
}