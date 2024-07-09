
rule Trojan_Win32_Formbook_MK_MTB{
	meta:
		description = "Trojan:Win32/Formbook.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 45 f4 7a 23 00 00 0f bf 15 ?? ?? ?? ?? 83 f2 ?? 0f bf 05 ?? ?? ?? ?? 3b d0 90 13 c7 45 f8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 39 0d ?? ?? ?? ?? 7f 07 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Formbook_MK_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 83 c4 0c 57 68 80 00 00 00 6a 03 57 6a 01 68 00 00 00 80 ff 70 04 ff 15 } //10
		$a_03_1 = {6a 40 68 00 30 00 00 50 57 89 45 f0 ff 15 ?? ?? ?? ?? 57 8b d8 8d 45 d4 50 ff 75 f0 53 56 ff 15 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Formbook_MK_MTB_3{
	meta:
		description = "Trojan:Win32/Formbook.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {52 69 6e 4b 65 72 79 67 6d 61 } //1 RinKerygma
		$a_81_1 = {44 72 61 77 49 6e 63 69 73 75 72 65 36 34 } //1 DrawIncisure64
		$a_81_2 = {44 69 73 61 62 6c 65 41 78 69 6c } //1 DisableAxil
		$a_81_3 = {54 6f 47 61 6e 67 77 61 79 } //1 ToGangway
		$a_81_4 = {52 65 6a 65 63 74 53 65 6c 65 6e 69 75 6d 2e 64 6c 6c } //1 RejectSelenium.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Formbook_MK_MTB_4{
	meta:
		description = "Trojan:Win32/Formbook.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {52 65 63 65 69 76 65 4b 6e 69 74 36 34 } //ReceiveKnit64  1
		$a_80_1 = {42 65 67 69 6e 4c 61 77 6e 33 32 } //BeginLawn32  1
		$a_80_2 = {52 65 6c 65 61 73 65 53 65 72 61 67 6c 69 6f } //ReleaseSeraglio  1
		$a_80_3 = {4c 65 61 72 6e 47 6c 6f 73 73 61 36 34 } //LearnGlossa64  1
		$a_80_4 = {52 65 63 65 69 76 65 41 62 65 74 74 6f 72 33 32 } //ReceiveAbettor32  1
		$a_80_5 = {42 65 6c 69 65 76 65 45 73 74 68 65 73 69 61 36 34 2e 64 6c 6c } //BelieveEsthesia64.dll  1
		$a_80_6 = {53 75 6e 68 61 74 73 } //Sunhats  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}
rule Trojan_Win32_Formbook_MK_MTB_5{
	meta:
		description = "Trojan:Win32/Formbook.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 cf 10 c1 cb ?? 33 fb 8b da 81 e3 ?? ?? ?? ?? 0f b6 1c 9d ?? ?? ?? ?? 8b 1c 9d ?? ?? ?? ?? c1 ea ?? 0f b6 14 95 90 1b 02 c1 c3 90 1b 00 33 fb 33 3c 95 90 1b 03 89 79 ?? 4e 0f 85 } //1
		$a_03_1 = {33 cf 81 e2 ?? ?? ?? ?? 33 ca 33 48 ?? 89 48 ?? 8b 50 ?? 33 d1 8b 48 ?? 33 ca 89 50 ?? 8b 50 ?? 33 d1 89 48 ?? 89 50 ?? 83 c6 ?? 83 c0 90 1b 08 83 fe ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Formbook_MK_MTB_6{
	meta:
		description = "Trojan:Win32/Formbook.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {44 00 72 00 61 00 77 00 54 00 69 00 74 00 6d 00 6f 00 75 00 73 00 65 00 } //1 DrawTitmouse
		$a_00_1 = {53 00 74 00 61 00 72 00 74 00 50 00 61 00 73 00 74 00 65 00 6c 00 } //1 StartPastel
		$a_01_2 = {47 61 6c 6c 69 77 61 73 70 } //1 Galliwasp
		$a_00_3 = {46 00 69 00 6e 00 64 00 4f 00 6c 00 69 00 67 00 61 00 72 00 63 00 68 00 36 00 34 00 } //1 FindOligarch64
		$a_00_4 = {4c 00 65 00 61 00 64 00 42 00 6f 00 6e 00 67 00 6f 00 33 00 32 00 } //1 LeadBongo32
		$a_01_5 = {5f 4c 6f 73 65 46 72 69 74 68 73 74 6f 6f 6c 2e 64 6c 6c } //1 _LoseFrithstool.dll
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}
rule Trojan_Win32_Formbook_MK_MTB_7{
	meta:
		description = "Trojan:Win32/Formbook.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_80_0 = {55 6e 6c 6f 61 64 6d 61 70 4e 69 70 70 6c 65 77 6f 72 74 } //UnloadmapNipplewort  1
		$a_80_1 = {42 72 69 6e 67 50 69 6e 75 70 } //BringPinup  1
		$a_80_2 = {57 69 6e 45 73 74 61 62 6c 69 73 68 6d 65 6e 74 61 72 69 61 6e } //WinEstablishmentarian  1
		$a_80_3 = {55 6e 68 6f 6f 6b 46 69 64 64 6c 65 62 61 63 6b } //UnhookFiddleback  1
		$a_80_4 = {43 61 72 72 79 50 6c 61 79 6d 61 74 65 } //CarryPlaymate  1
		$a_80_5 = {53 77 69 74 63 68 50 79 65 6c 6f 67 72 61 70 68 79 33 32 } //SwitchPyelography32  1
		$a_80_6 = {52 65 6c 65 61 73 65 59 75 61 6e 33 32 2e 64 6c 6c } //ReleaseYuan32.dll  1
		$a_80_7 = {53 74 72 65 70 74 6f 6b 69 6e 61 73 65 } //Streptokinase  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=7
 
}