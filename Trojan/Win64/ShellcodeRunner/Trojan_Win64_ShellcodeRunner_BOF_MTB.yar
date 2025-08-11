
rule Trojan_Win64_ShellcodeRunner_BOF_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.BOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 2d 70 08 00 00 0f b6 00 48 8b 95 08 08 00 00 48 89 d1 48 0f af 8d e8 07 00 00 48 8b 95 00 08 00 00 48 01 d1 48 8b 95 d0 07 00 00 48 01 ca 32 85 ff 07 00 00 88 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}