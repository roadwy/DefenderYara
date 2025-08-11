
rule Trojan_Win32_KillFiles_SX_MTB{
	meta:
		description = "Trojan:Win32/KillFiles.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c9 8b c7 ba 02 00 00 00 f7 e2 0f 90 90 c1 f7 d9 0b c8 51 e8 ?? ?? ?? ?? 83 c4 04 8b f0 57 8d 84 24 04 03 00 00 50 56 e8 ?? ?? ?? ?? 8b c6 83 c4 0c 8d 48 02 } //3
		$a_01_1 = {8b c8 c1 e9 02 8b f2 f3 a5 8b c8 83 e1 03 f3 a4 8d 7d a0 4f 8d 49 00 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}