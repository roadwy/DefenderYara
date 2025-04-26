
rule Backdoor_Win32_Poison_CD{
	meta:
		description = "Backdoor:Win32/Poison.CD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 6e 73 69 67 6e 65 64 20 63 68 61 72 20 66 75 63 6b 79 6f 75 } //1 unsigned char fuckyou
		$a_03_1 = {56 2b c8 8d 72 01 8a 14 ?? 80 f2 ?? 88 10 40 4e 75 ?? 5e c3 } //1
		$a_01_2 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 41 00 63 00 74 00 69 00 76 00 65 00 73 00 2e 00 65 00 78 00 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Backdoor_Win32_Poison_CD_2{
	meta:
		description = "Backdoor:Win32/Poison.CD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 85 f6 ?? ?? 03 cb 8a 54 07 ?? 32 14 29 40 3b c6 88 ?? ?? ?? 8b 4c 24 ?? 8b 54 24 ?? 8d 42 ?? 3b d8 ?? ?? 51 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 4c ?? ?? 8b 54 ?? ?? 83 c4 ?? 43 3b da 72 } //1
		$a_03_1 = {77 11 8a 98 ?? ?? ?? ?? 32 da 80 eb ?? 88 98 ?? ?? ?? ?? 8d bc 06 ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 77 11 8a 98 ?? ?? ?? ?? 32 d9 80 eb ?? 88 98 ?? ?? ?? ?? 83 c0 ?? 3d ?? ?? ?? ?? 7e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule Backdoor_Win32_Poison_CD_3{
	meta:
		description = "Backdoor:Win32/Poison.CD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_00_0 = {eb 73 e8 2e 00 00 00 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e 00 } //5
		$a_02_1 = {73 74 75 62 70 61 74 68 ?? ?? ?? ?? 73 6f 66 74 77 61 72 65 5c 63 6c 61 73 73 65 73 5c 68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 76 } //3
		$a_00_2 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 61 63 74 69 76 65 20 73 65 74 75 70 5c 69 6e 73 74 61 6c 6c 65 64 20 63 6f 6d 70 6f 6e 65 6e 74 73 5c } //1 software\microsoft\active setup\installed components\
		$a_00_3 = {61 64 76 70 61 63 6b } //1 advpack
	condition:
		((#a_00_0  & 1)*5+(#a_02_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=10
 
}