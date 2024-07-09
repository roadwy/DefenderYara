
rule Trojan_Win32_Fileson_A{
	meta:
		description = "Trojan:Win32/Fileson.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {65 73 6f 6e 69 63 2e 63 6f 6d 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 47 45 54 20 2f 6c 69 6e 6b 3f 6d 65 74 68 6f 64 3d 67 65 74 44 6f 77 6e 6c 6f 61 64 4c 69 6e 6b 26 66 6f 72 6d 61 74 3d 78 6d 6c 26 75 3d } //1
		$a_00_1 = {26 70 61 73 73 77 6f 72 64 3d } //1 &password=
		$a_00_2 = {75 7a 7a 79 2e } //1 uzzy.
		$a_00_3 = {66 73 6e 31 2e 64 6c 6c 00 4c 33 32 } //1 獦ㅮ搮汬䰀㈳
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}