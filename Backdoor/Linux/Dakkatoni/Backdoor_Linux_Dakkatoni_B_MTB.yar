
rule Backdoor_Linux_Dakkatoni_B_MTB{
	meta:
		description = "Backdoor:Linux/Dakkatoni.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_00_0 = {31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 65 20 13 06 68 02 00 11 5c 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 4e 74 3d 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd eb 27 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Linux_Dakkatoni_B_MTB_2{
	meta:
		description = "Backdoor:Linux/Dakkatoni.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {0f b6 17 32 16 30 c2 0f 44 d0 83 e8 01 48 83 c7 01 88 16 48 83 c6 01 3c e3 75 e5 f3 c3 } //01 00 
		$a_00_1 = {89 c2 48 bb 2f 2e 62 61 73 68 5f 70 c1 ea 10 a9 80 80 00 00 0f 44 c2 48 8d 51 02 48 0f 44 ca 00 c0 48 83 d9 03 48 89 19 c7 41 08 72 6f 66 69 66 c7 41 0c 6c 65 c6 41 0e 00 48 89 e7 e8 2e fd ff ff 48 ba 2f 65 74 63 2f 72 63 2e 48 b8 64 2f 72 63 2e 6c 6f 63 48 89 e7 48 89 14 24 48 89 44 24 08 66 c7 44 24 10 61 6c c6 44 24 12 00 e8 fd fc ff ff 48 81 c4 08 02 00 00 5b } //01 00 
		$a_00_2 = {2f 74 6d 70 2f 41 6e 74 69 56 69 72 74 6d 70 } //01 00  /tmp/AntiVirtmp
		$a_00_3 = {70 79 74 68 6f 6e 20 2d 63 20 27 69 6d 70 6f 72 74 20 70 74 79 3b 70 74 79 2e 73 70 61 77 6e 28 22 2f 62 69 6e 2f 73 68 } //00 00  python -c 'import pty;pty.spawn("/bin/sh
	condition:
		any of ($a_*)
 
}