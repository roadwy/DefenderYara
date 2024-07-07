
rule Backdoor_Win64_Turla_SK_MTB{
	meta:
		description = "Backdoor:Win64/Turla.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ca 81 e1 ff 00 00 80 7d 90 01 01 ff c9 81 c9 00 ff ff ff ff c1 43 90 01 04 32 c1 34 90 01 01 41 88 00 ff c2 49 ff c0 83 fa 90 01 01 72 90 00 } //5
		$a_02_1 = {48 c7 45 a0 90 01 04 48 89 7d 98 66 89 7d 88 48 8d 55 e8 48 83 7d 90 01 02 48 0f 43 55 e8 45 33 c0 33 c9 ff 15 90 01 04 48 c7 45 80 90 01 04 48 89 7c 24 78 66 89 7c 24 68 49 83 c9 ff 45 33 c0 48 8d 55 e8 48 8d 4c 24 68 e8 90 01 04 48 8d 4c 24 68 e8 90 01 04 84 c0 75 90 01 01 e8 90 01 04 33 c9 ff 15 90 00 } //2
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*2) >=7
 
}