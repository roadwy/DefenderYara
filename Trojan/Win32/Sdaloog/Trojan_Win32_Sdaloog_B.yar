
rule Trojan_Win32_Sdaloog_B{
	meta:
		description = "Trojan:Win32/Sdaloog.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {81 7d 00 50 45 00 00 0f 85 ?? ?? ?? ?? 6a 04 68 00 30 00 00 ff 75 50 ff 75 34 ff } //1
		$a_03_1 = {c0 e0 04 2c 10 0a c3 32 c1 32 [0-05] 88 06 32 e8 [0-06] eb 0e } //1
		$a_01_2 = {8b 41 04 8a 00 32 01 a2 } //1
		$a_00_3 = {57 54 53 45 6e 75 6d 65 72 61 74 65 53 65 73 73 69 6f 6e 73 41 00 } //1 呗䕓畮敭慲整敓獳潩獮A
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}