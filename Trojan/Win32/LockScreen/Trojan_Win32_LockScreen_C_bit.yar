
rule Trojan_Win32_LockScreen_C_bit{
	meta:
		description = "Trojan:Win32/LockScreen.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {56 57 8b 3d ?? ?? ?? ?? 81 e7 00 00 ff ff 0f b7 07 69 c0 ?? ?? ?? ?? 3d ?? ?? ?? ?? 74 1b } //1
		$a_03_1 = {0f b7 8f 00 00 ff ff 81 ef 00 00 01 00 69 c9 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75 e5 } //1
		$a_01_2 = {34 0e 66 0f b6 c0 41 66 89 02 8a 01 83 c2 02 3c 0e 75 ed } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}