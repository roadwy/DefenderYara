
rule Backdoor_MacOS_Gimmick_A_MTB{
	meta:
		description = "Backdoor:MacOS/Gimmick.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,08 00 08 00 05 00 00 05 00 "
		
	strings :
		$a_02_0 = {fe c9 48 81 fa c8 00 00 00 75 90 01 01 48 c7 c3 fe ff ff ff 4c 8d 25 aa 88 04 00 4c 8d 35 e9 f7 02 00 4c 8d bd ac fb ff ff 41 bd 02 00 00 00 c6 85 ae fb ff ff 00 66 c7 85 ac fb ff ff 00 00 0f be 94 1d b2 fb ff ff 0f be 8c 1d b3 fb ff ff 4c 89 ff 4c 89 f6 31 c0 e8 90 01 04 4c 89 ff 31 f6 ba 10 00 00 00 e8 90 01 04 41 88 04 24 4c 01 eb 49 ff c4 48 83 fb 1e 72 90 01 01 48 8d bd e0 fb ff ff e8 90 01 04 8b 3d 85 83 04 00 90 00 } //05 00 
		$a_02_1 = {29 05 00 91 3f 21 03 f1 21 90 01 03 14 00 80 d2 b5 74 23 10 1f 20 03 d5 f6 83 00 91 93 64 18 50 1f 20 03 d5 ff 7b 00 39 ff 3b 00 79 c8 02 14 8b 09 01 80 39 08 05 80 39 e9 23 00 a9 e0 73 00 91 e1 03 13 aa ad 90 01 03 e0 73 00 91 01 00 80 d2 02 02 80 52 c1 90 01 03 a0 16 00 38 88 0a 00 91 9f 7a 00 f1 f4 03 08 aa e3 90 01 03 e0 43 01 91 3f 90 01 03 68 4c 23 30 90 00 } //01 00 
		$a_00_2 = {43 72 65 64 73 51 75 65 75 65 } //01 00  CredsQueue
		$a_00_3 = {44 72 69 76 65 55 70 6c 6f 61 64 51 75 65 75 65 } //01 00  DriveUploadQueue
		$a_03_4 = {74 74 70 73 3a 2f 2f 90 02 25 2f 75 70 6c 6f 61 64 2f 64 72 69 76 65 2f 76 33 2f 66 69 6c 65 73 3f 61 6c 74 3d 6a 73 6f 6e 26 75 70 6c 6f 61 64 54 79 70 65 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}