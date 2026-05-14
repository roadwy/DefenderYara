
rule Trojan_Win64_ShellcodeRunner_AVD_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.AVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 c9 3f 00 01 00 48 8d 52 ?? 0f b6 c0 03 c8 0f b6 02 84 c0 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}