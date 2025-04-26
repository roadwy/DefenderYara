
rule Trojan_Win64_ShellcodeRunner_MKV_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 c0 4c 8d 0d ?? ?? ?? ?? 4c 2b c8 48 8b c8 66 ?? 41 0f b6 14 09 48 8d 49 01 80 ea 06 41 ff c0 88 51 ff 41 83 f8 0c 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}