
rule Trojan_Win64_ShellcodeRunner_CM_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 39 d2 74 4e 8d 4b 01 0f b6 d9 0f b6 c9 8a 84 0c 90 01 02 00 00 46 8d 04 18 45 0f b6 d8 45 0f b6 c0 42 8a b4 04 90 01 02 00 00 40 88 b4 0c 90 01 02 00 00 42 88 84 04 90 01 02 00 00 02 84 0c 90 01 02 00 00 0f b6 c0 8a 84 04 90 01 02 00 00 41 30 04 11 48 ff c2 eb 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}