
rule Trojan_Win64_Vidar_ABV_MTB{
	meta:
		description = "Trojan:Win64/Vidar.ABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 47 01 0f b6 f8 48 8d 52 01 0f b6 4c 3c 50 42 8d 04 01 44 0f b6 c0 42 0f b6 44 04 50 88 44 3c 50 42 88 4c 04 50 0f b6 44 3c 50 03 c1 0f b6 c0 0f b6 4c 04 50 30 4a ff 49 83 e9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Vidar_ABV_MTB_2{
	meta:
		description = "Trojan:Win64/Vidar.ABV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff ca 0b d5 ff c2 48 63 ca 8a 44 0c ?? 88 44 1c ?? 44 88 54 0c ?? 0f b6 44 1c ?? 41 03 c2 0f b6 c0 8a 4c 04 ?? 41 30 08 49 ff c0 49 83 eb } //5
		$a_03_1 = {44 30 ac 05 ?? ?? ?? ?? 49 03 c4 48 83 f8 } //4
		$a_80_2 = {70 41 4a 43 47 77 56 40 47 41 5c 4a 78 56 4a } //pAJCGwV@GA\JxVJ  1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4+(#a_80_2  & 1)*1) >=10
 
}