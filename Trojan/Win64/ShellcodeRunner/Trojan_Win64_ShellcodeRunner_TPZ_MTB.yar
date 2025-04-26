
rule Trojan_Win64_ShellcodeRunner_TPZ_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.TPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 8d 00 01 00 00 48 03 c8 48 8b c1 0f b6 00 0f b6 8d ?? ?? ?? ?? 33 c1 48 8b 4d 08 48 8b 95 00 01 00 00 48 03 d1 48 8b ca 88 01 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}