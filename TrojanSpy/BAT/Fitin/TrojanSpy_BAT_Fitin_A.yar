
rule TrojanSpy_BAT_Fitin_A{
	meta:
		description = "TrojanSpy:BAT/Fitin.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 32 31 30 63 43 35 6e 62 57 46 70 62 43 35 6a 62 32 30 3d } //01 00  c210cC5nbWFpbC5jb20=
		$a_01_1 = {58 45 5a 70 62 47 56 6b 54 6d 46 74 5a 53 35 6c 65 47 55 3d } //01 00  XEZpbGVkTmFtZS5leGU=
		$a_01_2 = {55 32 39 6d 64 48 64 68 63 6d 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 46 64 70 62 6d 52 76 64 33 4e 63 51 33 56 79 63 6d 56 75 64 46 5a 6c 63 6e 4e 70 62 32 35 63 55 6e 56 75 } //01 00  U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu
		$a_01_3 = {58 54 6f 67 55 48 4a 76 5a 33 4a 68 62 53 42 4a 63 79 42 50 5a 6d 59 67 54 6d 39 33 } //01 00  XTogUHJvZ3JhbSBJcyBPZmYgTm93
		$a_01_4 = {58 54 6f 67 54 6d 56 33 49 45 6c 75 5a 6d 56 6a 64 47 6c 76 62 67 3d 3d } //01 00  XTogTmV3IEluZmVjdGlvbg==
		$a_01_5 = {54 6d 56 33 49 45 6c 75 5a 6d 56 6a 64 47 6c 76 62 69 45 68 49 51 3d 3d } //01 00  TmV3IEluZmVjdGlvbiEhIQ==
		$a_01_6 = {57 30 4a 68 59 32 74 7a 63 47 46 6a 5a 56 30 3d } //00 00  W0JhY2tzcGFjZV0=
		$a_00_7 = {5d 04 00 } //00 5f 
	condition:
		any of ($a_*)
 
}