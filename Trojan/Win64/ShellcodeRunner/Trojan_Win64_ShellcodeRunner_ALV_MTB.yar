
rule Trojan_Win64_ShellcodeRunner_ALV_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.ALV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 ff c1 49 63 c9 48 8d 95 ?? ?? ?? ?? 48 03 d1 0f b6 0a 41 88 0b 44 88 02 45 02 03 41 0f b6 d0 44 0f b6 84 15 ?? ?? ?? ?? 45 30 02 49 ff c2 48 83 eb 01 75 92 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}