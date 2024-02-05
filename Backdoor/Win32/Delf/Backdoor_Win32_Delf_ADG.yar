
rule Backdoor_Win32_Delf_ADG{
	meta:
		description = "Backdoor:Win32/Delf.ADG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 53 68 d8 49 40 00 6a 00 e8 65 fb ff ff 33 c0 e8 b2 e9 ff ff eb 1b 8d 55 c8 b8 01 00 00 00 e8 4f e0 ff ff 8b 45 c8 e8 ff eb ff ff 50 e8 21 f1 ff ff a1 50 69 40 00 ba e8 49 40 00 e8 36 eb ff ff 0f 85 c0 00 00 00 8d 45 c4 e8 90 fb ff ff ff 75 c4 68 c4 49 40 00 8d 55 bc 33 c0 e8 12 e0 ff ff 8b 45 bc 8d 55 c0 e8 e7 fc ff ff ff 75 c0 b8 5c 69 40 00 ba 03 00 00 00 } //01 00 
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c } //01 00 
		$a_01_2 = {57 69 6e 33 32 20 53 65 72 76 69 63 65 } //01 00 
		$a_01_3 = {73 61 75 3d 79 65 73 3f 3f 3f } //01 00 
		$a_01_4 = {6c 6f 6c 2e 68 74 6d 6c } //01 00 
		$a_01_5 = {73 79 73 33 32 } //00 00 
	condition:
		any of ($a_*)
 
}