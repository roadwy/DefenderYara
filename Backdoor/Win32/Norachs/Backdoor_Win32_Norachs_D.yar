
rule Backdoor_Win32_Norachs_D{
	meta:
		description = "Backdoor:Win32/Norachs.D,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 1c 00 00 "
		
	strings :
		$a_01_0 = {43 53 6f 63 6b 65 74 4d 61 73 74 65 72 00 00 00 4d 6f 64 75 6c 65 31 00 44 4f 53 4f 75 74 70 75 74 73 00 00 4d 61 69 6e 46 6f 72 6d 00 00 00 00 } //1
		$a_01_1 = {8d 4d 98 0f 94 c0 f7 d8 66 89 85 50 ff ff ff e8 09 cf fc ff 66 39 b5 50 ff ff ff 74 75 8b 03 53 ff 90 04 03 00 00 50 8d 45 98 50 e8 0b cf fc ff 83 ec } //1
		$a_01_2 = {10 8d b5 74 ff ff ff 8b fc c7 85 7c ff ff ff 04 00 02 80 c7 85 74 ff ff ff 0a 00 00 00 8b 08 a5 a5 a5 68 3c fb 40 00 50 89 85 58 ff ff ff a5 ff 91 ec } //1
		$a_01_3 = {01 00 00 85 c0 db e2 7d 16 68 ec 01 00 00 68 28 ee 40 00 ff b5 58 ff ff ff 50 e8 a6 ce fc ff 8d 4d 98 e8 92 ce fc ff 33 f6 bf 28 ee 40 00 8b 03 53 ff } //1
		$a_01_4 = {90 04 03 00 00 50 8d 45 98 50 e8 96 ce fc ff 8b 08 56 50 89 85 58 ff ff ff ff 91 e4 00 00 00 3b c6 db e2 7d 12 68 e4 00 00 00 57 ff b5 58 ff ff ff 50 } //1
		$a_01_5 = {e8 5c ce fc ff 8d 4d 98 e8 48 ce fc ff 8b 03 53 ff 90 04 03 00 00 50 8d 45 98 50 e8 53 ce fc ff 8b 08 8d 95 60 ff ff ff 52 50 89 85 58 ff ff ff ff 91 } //1
		$a_01_6 = {e0 00 00 00 3b c6 db e2 7d 12 68 e0 00 00 00 57 ff b5 58 ff ff ff 50 e8 13 ce fc ff 66 8b 85 60 ff ff ff 8d 95 74 ff ff ff 8d 4d c8 66 89 85 7c ff ff } //1
		$a_01_7 = {ff c7 85 74 ff ff ff 02 00 00 00 e8 d9 cf fc ff 8d 4d 98 e8 d9 cd fc ff 8b 03 53 ff 90 04 03 00 00 50 8d 45 98 50 e8 e4 cd fc ff 8b 08 8d 55 a0 52 50 } //1
		$a_01_8 = {89 85 58 ff ff ff ff 91 f8 00 00 00 3b c6 db e2 7d 12 68 f8 00 00 00 57 ff b5 58 ff ff ff 50 e8 a7 cd fc ff ff 75 a0 68 3c fb 40 00 e8 2c cc fc ff 8b } //1
		$a_01_9 = {f8 8d 4d a0 f7 df 1b ff 47 f7 df e8 83 cd fc ff 8d 4d 98 e8 75 cd fc ff 66 3b fe 74 4b 83 ec 10 8d b5 74 ff ff ff 8b fc c7 85 7c ff ff ff 4c fb 40 00 } //1
		$a_01_10 = {c7 85 74 ff ff ff 08 00 00 00 8b 03 a5 a5 a5 6a 01 68 1e 00 03 60 53 a5 ff 90 0c 03 00 00 50 8d 45 98 50 e8 51 cd fc ff 50 e8 19 cf fc ff 83 c4 1c e9 } //1
		$a_01_11 = {71 02 00 00 8b 03 53 ff 90 a8 07 00 00 8d 85 60 ff ff ff 89 b5 60 ff ff ff 50 8d 45 dc 56 50 e8 3b cd fc ff 50 8d 45 a8 50 e8 31 cd fc ff 50 e8 63 1d } //1
		$a_01_12 = {fd ff e8 d8 cc fc ff 8b 03 53 ff 90 ac 07 00 00 39 35 74 9c 43 00 75 0f 68 74 9c 43 00 68 c8 bb 40 00 e8 a6 cc fc ff 8b 3d 74 9c 43 00 8d 4d 98 51 57 } //1
		$a_01_13 = {8b 07 ff 50 1c 3b c6 db e2 7d 11 bb b8 bb 40 00 6a 1c 53 57 50 e8 b7 cc fc ff eb 05 bb b8 bb 40 00 8d 55 94 8d b5 74 ff ff ff 52 c7 85 7c ff ff ff 04 } //1
		$a_01_14 = {00 02 80 83 ec 10 c7 85 74 ff ff ff 0a 00 00 00 8b fc 8b 45 98 a5 8b 08 50 a5 a5 89 85 50 ff ff ff a5 ff 51 54 85 c0 db e2 7d 13 6a 54 68 b0 fa 40 00 } //1
		$a_01_15 = {ff b5 50 ff ff ff 50 e8 61 cc fc ff 8b 45 94 83 ec 10 8d 75 84 8b fc 89 45 8c c7 45 84 09 00 00 00 a5 a5 83 65 94 00 8d 45 b8 a5 68 5c fb 40 00 50 a5 } //1
		$a_01_16 = {e8 ac ce fc ff 8d 4d 98 e8 22 cc fc ff 8d 4d 84 e8 d2 cb fc ff 6a 00 8d 45 b8 68 6c fb 40 00 50 8d 45 84 50 e8 74 cd fc ff 83 c4 10 83 3d 74 9c 43 00 } //1
		$a_01_17 = {00 75 0f 68 74 9c 43 00 68 c8 bb 40 00 e8 c1 cb fc ff 8b 35 74 9c 43 00 68 f0 f1 40 00 8d 45 84 68 78 fb 40 00 8b 3e 50 e8 46 cb fc ff 50 8d 45 98 50 } //1
		$a_01_18 = {e8 e4 cb fc ff 50 56 ff 57 40 85 c0 db e2 7d 0a 6a 40 53 56 50 e8 bd cb fc ff 8d 4d 98 e8 a9 cb fc ff 8d 4d 84 e8 59 cb fc ff e8 58 ca fc ff 83 8d 5c } //1
		$a_01_19 = {ff ff ff ff 8d 85 5c ff ff ff 50 e8 eb ba fd ff 8b d0 8d 4d a0 e8 a3 cb fc ff be 8c fb 40 00 50 56 e8 0d cb fc ff 8b d0 8d 4d 9c e8 8d cb fc ff 8d 45 } //1
		$a_01_20 = {9c 50 ff 75 0c e8 d3 e8 fe ff 8d 45 9c 50 8d 45 a0 50 6a 02 e8 18 cb fc ff 83 8d 5c ff ff ff ff 83 c4 0c 8d 85 5c ff ff ff 50 e8 9a ba fd ff 8b d0 8d } //1
		$a_01_21 = {4d a0 e8 52 cb fc ff 50 56 e8 c1 ca fc ff 8b d0 8d 4d d8 e8 41 cb fc ff 8d 4d a0 e8 1b cb fc ff e8 cc c9 fc ff e8 c7 c9 fc ff 83 3d 74 9c 43 00 00 75 } //1
		$a_01_22 = {0f 68 74 9c 43 00 68 c8 bb 40 00 e8 c9 ca fc ff 8b 35 74 9c 43 00 8d 4d 98 51 56 8b 06 ff 50 1c 85 c0 db e2 7d 0a 6a 1c 53 56 50 e8 df ca fc ff 8b 45 } //1
		$a_01_23 = {98 50 8b f0 8b 08 ff 51 50 85 c0 db e2 7d 0e 6a 50 68 b0 fa 40 00 56 50 e8 c0 ca fc ff 8d 4d 98 e8 ac ca fc ff 68 da 75 43 00 eb 38 f6 45 fc 04 74 08 } //1
		$a_01_24 = {8d 4d d8 e8 9d ca fc ff 8d 45 9c 50 8d 45 a0 50 6a 02 e8 52 ca fc ff 8d 45 94 50 8d 45 98 50 6a 02 e8 3b cc fc ff 83 c4 18 8d 4d 84 e8 26 ca fc ff c3 } //1
		$a_01_25 = {8d 4d dc e8 1d ca fc ff 8d 4d c8 e8 15 ca fc ff 8d 4d b8 e8 0d ca fc ff 8d 4d a8 e8 05 ca fc ff 8d 4d a4 e8 45 ca fc ff c3 8b 45 08 50 8b 08 ff 51 08 } //1
		$a_01_26 = {8b 45 10 8b 4d d8 89 08 8b 45 fc 8b 4d ec 5f 5e 64 89 0d 00 00 00 00 5b c9 c2 0c 00 cc 9e 9e 9e 9e } //1
		$a_01_27 = {43 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 63 00 68 00 72 00 69 00 73 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 4f 00 6d 00 65 00 72 00 74 00 61 00 20 00 31 00 2e 00 33 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 6d 00 69 00 6e 00 67 00 5c 00 53 00 65 00 72 00 76 00 65 00 72 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 C*\AC:\Documents and Settings\chris\Desktop\Omerta 1.3 Programming\Server\Project1.vbp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1) >=28
 
}