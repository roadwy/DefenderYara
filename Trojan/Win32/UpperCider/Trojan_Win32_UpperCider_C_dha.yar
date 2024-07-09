
rule Trojan_Win32_UpperCider_C_dha{
	meta:
		description = "Trojan:Win32/UpperCider.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_81_0 = {78 6c 41 75 74 6f 4f 70 65 6e } //3 xlAutoOpen
		$a_81_1 = {52 65 67 69 73 74 65 72 58 4c 4c 2e 64 6c 6c } //3 RegisterXLL.dll
		$a_03_2 = {ff ff ff 43 72 65 61 c7 45 ?? 74 65 52 65 c7 45 ?? 6d 6f 74 65 c7 45 ?? 54 68 72 65 66 c7 45 ?? 61 64 c6 45 ?? 00 c7 45 ?? ?? 65 72 6e c7 45 ?? 65 6c 33 32 c7 45 ?? 2e 64 6c 6c c6 45 ?? 00 ff ?? 50 ff ?? 68 04 01 00 00 8d 95 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b f0 ff 95 } //5
		$a_03_3 = {83 e8 04 83 c1 04 83 c7 04 83 f8 04 73 ?? 85 c0 74 ?? 8a 19 3a 1f 75 ?? 83 f8 01 76 ?? 8a 59 01 3a 5f 01 75 ?? 83 f8 02 76 ?? 8a 41 02 3a 47 02 75 ?? 5b b8 ?? ?? ?? ?? 5f 2b c6 } //5
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_03_2  & 1)*5+(#a_03_3  & 1)*5) >=10
 
}