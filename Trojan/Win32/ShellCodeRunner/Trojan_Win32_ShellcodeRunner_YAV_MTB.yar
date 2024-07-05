
rule Trojan_Win32_ShellcodeRunner_YAV_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.YAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 58 8d 14 07 03 54 24 28 0f b6 0c 01 83 c0 01 30 0a 39 c6 75 e8 } //00 00 
	condition:
		any of ($a_*)
 
}