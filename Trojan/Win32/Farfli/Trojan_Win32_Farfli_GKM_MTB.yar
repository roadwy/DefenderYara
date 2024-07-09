
rule Trojan_Win32_Farfli_GKM_MTB{
	meta:
		description = "Trojan:Win32/Farfli.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 10 80 f2 3d 80 c2 3d 88 10 83 c0 01 83 e9 01 75 } //1
		$a_02_1 = {8b f8 8b 46 ?? 03 44 24 ?? 52 50 57 e8 ?? ?? ?? ?? 89 7e ?? 83 c4 0c 8b 4c 24 ?? 8b 11 8b 44 24 ?? 0f b7 4a ?? 83 c0 01 83 c6 28 3b c1 89 44 24 ?? 0f 8c } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}