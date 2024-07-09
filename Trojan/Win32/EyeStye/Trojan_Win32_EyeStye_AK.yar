
rule Trojan_Win32_EyeStye_AK{
	meta:
		description = "Trojan:Win32/EyeStye.AK,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_02_0 = {c3 8b 45 0c 3d ?? ?? 00 00 75 ?? 8b 45 08 b9 ?? 00 00 00 f2 35 ?? ?? ?? ?? ff d0 90 09 03 00 (|?? f0 )} //10
		$a_00_1 = {0f b6 5c 15 00 45 83 fd 0f 75 05 bd 00 00 00 00 46 30 1f 47 3b f1 72 e8 } //2
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*2) >=12
 
}