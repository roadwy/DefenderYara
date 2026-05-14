
rule Trojan_Win64_Zusy_ARR_MTB{
	meta:
		description = "Trojan:Win64/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 79 65 63 74 6f 31 } //8 Proyecto1
		$a_01_1 = {00 4f 70 65 6e 48 74 6d 6c } //10
		$a_01_2 = {00 2b 33 71 b5 02 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*8+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2) >=20
 
}
rule Trojan_Win64_Zusy_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 24 60 32 c8 88 8c 15 ?? ?? ?? ?? 48 ff c2 48 83 fa } //11
		$a_01_1 = {0f b6 54 24 30 0f b6 4c 24 31 32 d1 88 54 04 3c 48 ff c0 48 83 f8 } //9
	condition:
		((#a_03_0  & 1)*11+(#a_01_1  & 1)*9) >=20
 
}
rule Trojan_Win64_Zusy_ARR_MTB_3{
	meta:
		description = "Trojan:Win64/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 0f 46 c8 41 c1 e0 ?? 66 41 89 09 4d 8d 49 ?? 49 ff ca 75 } //5
		$a_01_1 = {0f b6 c8 41 8b 00 d3 c8 41 33 c3 2b c2 41 89 00 4d 8d 40 } //15
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*15) >=20
 
}
rule Trojan_Win64_Zusy_ARR_MTB_4{
	meta:
		description = "Trojan:Win64/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 07 2c 11 07 8e 2c 0d 16 0a 08 07 28 ?? ?? ?? ?? 14 0b 2b 19 06 1b 2f 04 06 17 58 0a 1f 0f 06 5a 6c } //15
		$a_03_1 = {2b 07 08 07 28 ?? ?? ?? ?? de 18 26 de 15 } //5
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*5) >=20
 
}
rule Trojan_Win64_Zusy_ARR_MTB_5{
	meta:
		description = "Trojan:Win64/Zusy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {45 89 c2 41 c0 e2 ?? 48 ff c2 45 89 c8 45 08 d0 f6 c1 01 b1 } //13
		$a_03_1 = {49 01 d8 48 01 da 4c 89 f9 4d 89 e9 e8 ?? ?? ?? ?? 4c 89 f9 4c 89 f2 49 89 f8 4d 89 e9 } //5
		$a_81_2 = {24 54 72 69 67 67 65 72 5f 76 61 72 20 3d 20 4e 65 77 2d 53 63 68 65 64 75 6c 65 64 54 61 73 6b 54 72 69 67 67 65 72 20 2d 4f 6e 63 65 20 2d 41 74 20 28 47 65 74 2d 44 61 74 65 29 20 2d 52 65 70 65 74 69 74 69 6f 6e 49 6e 74 65 72 76 61 6c 20 28 4e 65 77 2d 54 69 6d 65 53 70 61 6e 20 2d 4d 69 6e 75 74 65 73 20 32 29 3b } //2 $Trigger_var = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2);
	condition:
		((#a_03_0  & 1)*13+(#a_03_1  & 1)*5+(#a_81_2  & 1)*2) >=20
 
}