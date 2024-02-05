
rule Trojan_Win32_EyeStye_AK{
	meta:
		description = "Trojan:Win32/EyeStye.AK,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c3 8b 45 0c 3d 90 01 02 00 00 75 90 01 01 8b 45 08 b9 90 01 01 00 00 00 f2 35 90 01 04 ff d0 90 09 03 00 90 03 00 03 90 01 01 f0 90 00 } //02 00 
		$a_00_1 = {0f b6 5c 15 00 45 83 fd 0f 75 05 bd 00 00 00 00 46 30 1f 47 3b f1 72 e8 } //00 00 
	condition:
		any of ($a_*)
 
}