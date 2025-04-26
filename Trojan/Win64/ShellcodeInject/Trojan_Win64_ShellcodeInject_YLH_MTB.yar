
rule Trojan_Win64_ShellcodeInject_YLH_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.YLH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 0f 1f 44 00 00 80 31 aa 48 8d 49 01 48 83 e8 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}