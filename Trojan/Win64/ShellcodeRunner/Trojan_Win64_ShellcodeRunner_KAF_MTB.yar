
rule Trojan_Win64_ShellcodeRunner_KAF_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 ff c1 48 31 c0 8b 04 8e 41 51 4d 31 c9 49 ff c1 4d 85 c9 0f 84 90 01 04 41 59 48 01 d8 4c 39 08 90 00 } //01 00 
		$a_03_1 = {4d 31 c0 4d 85 c0 0f 85 90 01 04 49 ff c0 4d 85 c0 0f 84 90 01 04 41 58 48 01 d8 4c 39 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}