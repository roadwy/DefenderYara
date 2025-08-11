
rule Trojan_Win32_ShellcodeLoader_MRZ_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeLoader.MRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 94 8d ?? ?? ?? ?? 88 55 ea 8b 55 f0 0f b6 4d ea 30 0c 32 46 ff 4d e4 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}