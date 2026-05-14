
rule Trojan_Win64_Lazy_ARR_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_81_0 = {43 33 7a 77 33 76 66 31 62 6e 38 4a 61 51 79 31 } //15 C3zw3vf1bn8JaQy1
		$a_81_1 = {4c 4c 49 65 6c 44 6d 45 53 33 31 4b 53 68 41 41 } //5 LLIelDmES31KShAA
	condition:
		((#a_81_0  & 1)*15+(#a_81_1  & 1)*5) >=20
 
}
rule Trojan_Win64_Lazy_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 05 00 00 "
		
	strings :
		$a_03_0 = {e0 13 00 00 ?? ?? bd 01 40 01 } //12
		$a_01_1 = {23 00 0b 02 0e 2c 00 b4 10 00 } //8
		$a_01_2 = {06 5a 1e 01 00 d0 10 00 } //5
		$a_01_3 = {3c 9b 00 00 00 30 2f 01 00 00 } //3
		$a_01_4 = {78 bd 00 00 00 d0 2f 01 00 00 } //2
	condition:
		((#a_03_0  & 1)*12+(#a_01_1  & 1)*8+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=30
 
}
rule Trojan_Win64_Lazy_ARR_MTB_3{
	meta:
		description = "Trojan:Win64/Lazy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {49 ff c1 42 0f b6 84 10 ?? ?? ?? ?? 42 32 84 11 ?? ?? ?? ?? 41 88 40 ff 41 81 fc } //10
		$a_03_1 = {42 0f b6 04 20 42 32 84 39 ?? ?? ?? ?? 41 88 01 41 ff c0 49 ff c2 4d 8d 49 } //8
		$a_03_2 = {ff c1 8b 45 ?? 99 f7 f9 89 45 00 e9 } //2
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*8+(#a_03_2  & 1)*2) >=20
 
}
rule Trojan_Win64_Lazy_ARR_MTB_4{
	meta:
		description = "Trojan:Win64/Lazy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 89 ee 41 80 f6 ?? 45 0f b6 f6 46 8d 34 75 01 00 00 00 41 bc ?? ?? ?? ?? 45 31 ed e9 4a } //30
		$a_01_1 = {4d 89 ec 49 d1 ec 48 89 c2 4c 29 e2 4d 01 ec 4c 39 e1 4c 0f 47 e1 49 39 d5 4c 89 e2 48 0f 47 d0 48 ff c2 } //20
		$a_03_2 = {45 0f b6 f6 46 8d 34 75 ?? ?? ?? ?? 41 bc 03 00 00 00 45 31 ed e9 4a } //10
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_03_2  & 1)*10) >=60
 
}