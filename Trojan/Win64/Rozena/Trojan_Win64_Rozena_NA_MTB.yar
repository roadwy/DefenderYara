
rule Trojan_Win64_Rozena_NA_MTB{
	meta:
		description = "Trojan:Win64/Rozena.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 f2 10 48 8d 3c f2 83 3d a2 4d 1b 00 ?? 75 09 4c 89 04 f2 } //3
		$a_03_1 = {75 24 48 8b 44 24 ?? 48 89 81 08 01 01 00 48 8b 05 4d d0 16 00 48 89 81 f8 00 01 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule Trojan_Win64_Rozena_NA_MTB_2{
	meta:
		description = "Trojan:Win64/Rozena.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 11 74 24 40 0f 11 7c 24 ?? 44 0f 11 44 24 ?? 83 39 06 0f 87 cd 00 00 00 8b 01 48 8d 15 ?? ?? ?? ?? 48 63 04 82 48 01 d0 } //3
		$a_03_1 = {48 8b 4c 24 20 48 8b 54 24 ?? 41 b8 40 00 00 00 48 03 3d ?? ?? ?? ?? 48 89 4f 08 49 89 f9 48 89 57 ?? ff 15 9c 5e 0c 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}