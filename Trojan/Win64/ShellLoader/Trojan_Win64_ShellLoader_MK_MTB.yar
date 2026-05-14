
rule Trojan_Win64_ShellLoader_MK_MTB{
	meta:
		description = "Trojan:Win64/ShellLoader.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 b8 02 00 00 00 49 3b c0 4c 0f 42 c0 49 8b d6 48 83 3d ?? ?? ?? ?? 0f 48 0f 47 15 ?? ?? ?? ?? 48 03 d7 48 8d 4c 24 30 } //35
	condition:
		((#a_03_0  & 1)*35) >=35
 
}