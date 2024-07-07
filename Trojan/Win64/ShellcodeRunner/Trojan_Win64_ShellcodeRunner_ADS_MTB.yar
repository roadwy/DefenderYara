
rule Trojan_Win64_ShellcodeRunner_ADS_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.ADS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c8 8b c1 25 ad 58 3a ff c1 e0 07 33 c8 8b c1 25 8c df ff ff c1 e0 0f 33 c8 8b c1 c1 e8 12 33 c1 49 3b c5 0f 87 67 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}