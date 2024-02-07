
rule Ransom_Win32_Cerber_ibt{
	meta:
		description = "Ransom:Win32/Cerber!ibt,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 61 74 6c 69 6e 2e 53 56 4d 66 } //01 00  Ratlin.SVMf
		$a_00_1 = {46 75 6b 6b 58 4d 45 6e } //01 00  FukkXMEn
		$a_00_2 = {52 4d 74 50 4d 71 2e 4c 42 4d 66 68 46 75 6b 6b 58 4d 45 6e } //01 00  RMtPMq.LBMfhFukkXMEn
		$a_00_3 = {48 72 65 46 74 66 46 69 6d 43 41 } //01 00  HreFtfFimCA
		$a_03_4 = {be 10 15 01 10 8d bc 24 34 01 00 00 8b 2d 90 01 04 f3 a5 66 8b 0d 90 01 04 33 c0 a4 8b 3d 90 01 04 89 84 24 49 01 00 00 23 cf 89 84 24 4d 01 00 00 66 85 c9 0f 85 ba 00 00 00 8a 0d 90 01 04 8b c5 d3 f8 85 c0 0f 85 a8 00 00 00 8a 0d 90 01 04 c0 f9 44 66 0f be c1 66 3b 05 08 12 01 10 0f 8e 8e 00 00 00 0f be 0d 9d 13 01 10 0f be d2 d1 e1 83 f2 2a 3b ca 7e 39 0f be 05 90 01 04 8a 0d da 10 01 10 d3 e0 0f bf 0d 90 01 04 c1 e1 bd 3b c8 7d 1c a0 96 10 01 10 8a 0d 90 01 04 8a d0 d2 fa 66 0f be ca 66 89 0d 90 01 04 eb 47 90 00 } //01 00 
		$a_03_5 = {8a d0 80 ca 7a 66 0f be ca 66 39 0d 90 01 04 7c 30 0f bf 15 90 01 04 8b 0d 90 01 04 c1 e2 a7 83 c9 27 3b d1 7d 19 a0 90 01 04 8a 0d 90 01 04 32 c1 a2 96 10 01 10 eb 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}