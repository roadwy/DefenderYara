
rule Backdoor_Win64_Brushworm_C_MTB{
	meta:
		description = "Backdoor:Win64/Brushworm.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_03_0 = {33 c9 ff 15 ?? ?? ?? ?? 89 44 24 ?? b9 01 00 00 00 ff 15 ?? ?? ?? ?? 89 44 24 ?? 81 7c 24 ?? 00 04 00 00 7f ?? 81 7c 24 ?? 00 03 00 00 7f } //5
		$a_03_1 = {48 8b 44 24 ?? 48 ff c0 48 89 44 24 ?? 48 8b 84 24 ?? ?? ?? ?? 48 39 44 24 ?? 73 48 48 6b 44 24 ?? 20 48 8b 8c 24 ?? ?? ?? ?? 48 03 c8 48 8b c1 48 8b c8 e8 ?? ?? ?? ?? c7 44 24 ?? 01 00 00 00 41 b9 ff ff ff ff 4c 8b c0 ba ff ff ff ff 48 8d 4c 24 ?? ff 15 } //5
		$a_01_2 = {73 00 61 00 6e 00 64 00 62 00 6f 00 78 00 } //1 sandbox
		$a_01_3 = {56 49 52 54 55 41 4c 42 4f 58 } //1 VIRTUALBOX
		$a_01_4 = {56 4d 57 41 52 45 } //1 VMWARE
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}