
rule Trojan_Win32_ShellcodeRunner_BAA_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeRunner.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 10 0f b6 14 10 23 f2 f7 d6 23 ce 8b 85 ?? ?? ?? ?? 03 45 98 88 08 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}