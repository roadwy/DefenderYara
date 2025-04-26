
rule TrojanSpy_AndroidOS_Origami_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Origami.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_00_0 = {54 33 56 30 52 32 39 70 62 6d 63 67 } //1 T3V0R29pbmcg
		$a_00_1 = {53 57 35 6a 62 32 31 70 62 6d 63 67 } //1 SW5jb21pbmcg
		$a_00_2 = {61 32 56 35 63 79 35 30 65 48 51 3d 20 } //1 a2V5cy50eHQ= 
		$a_00_3 = {62 33 4a 6e 4c 6e 52 6f 62 33 56 6e 61 48 52 6a 63 6d 6c 74 5a 53 35 7a 5a 57 4e 31 63 6d 56 7a 62 58 4d 76 4c 6d 4e 76 62 6e 5a 6c 63 6e 4e 68 64 47 6c 76 62 69 35 44 62 32 35 32 5a 58 4a 7a 59 58 52 70 62 32 35 42 59 33 52 70 64 6d 6c 30 65 51 3d 3d } //1 b3JnLnRob3VnaHRjcmltZS5zZWN1cmVzbXMvLmNvbnZlcnNhdGlvbi5Db252ZXJzYXRpb25BY3Rpdml0eQ==
		$a_00_4 = {59 32 39 74 4c 6e 64 6f 59 58 52 7a 59 58 42 77 4c 79 35 44 62 32 35 32 5a 58 4a 7a 59 58 52 70 62 32 34 3d } //1 Y29tLndoYXRzYXBwLy5Db252ZXJzYXRpb24=
		$a_00_5 = {51 32 46 73 62 45 78 76 5a 33 4d 75 64 48 68 30 } //1 Q2FsbExvZ3MudHh0
		$a_00_6 = {63 32 31 7a 4c 6e 52 34 64 41 3d 3d } //1 c21zLnR4dA==
		$a_00_7 = {51 32 56 73 62 45 6c 6b } //1 Q2VsbElk
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}