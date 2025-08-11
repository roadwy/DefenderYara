
rule Trojan_Win32_Storm_LM_MTB{
	meta:
		description = "Trojan:Win32/Storm.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c9 ff f2 ae f7 d1 2b f9 57 5e 52 5f 51 5a 83 c9 ff f2 ae 52 59 4f c1 e9 02 f3 a5 52 59 83 e1 03 f3 a4 51 8b cc 89 64 24 1c 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 65 51 8d 84 24 40 01 00 00 8b cc 89 64 24 24 50 } //20
		$a_01_1 = {83 c9 ff 29 c0 f2 ae f7 d1 2b f9 51 58 57 5e 52 5f 8d 54 24 10 c1 e9 02 f3 a5 50 59 29 c0 83 e1 03 f3 a4 } //20
		$a_00_2 = {53 54 4f 52 4d 53 45 52 56 45 52 2e 44 4c 4c } //1 STORMSERVER.DLL
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*20+(#a_00_2  & 1)*1) >=41
 
}