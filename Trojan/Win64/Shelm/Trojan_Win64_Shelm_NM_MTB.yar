
rule Trojan_Win64_Shelm_NM_MTB{
	meta:
		description = "Trojan:Win64/Shelm.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {4f 8d 04 27 41 b9 0d 00 00 00 4d 29 e1 4c 89 f1 48 89 fa e8 ?? ?? 00 00 0f b7 44 24 58 66 85 c0 75 ?? 4c 03 64 24 50 } //3
		$a_03_1 = {49 83 fc 0d 75 ?? 48 8d 15 dc 48 07 00 4c 8d 84 24 80 00 00 00 48 89 d9 e8 ?? ?? 01 00 66 85 c0 0f 84 ?? ?? 00 00 66 83 f8 10 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}