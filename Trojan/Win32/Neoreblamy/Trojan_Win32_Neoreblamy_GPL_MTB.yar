
rule Trojan_Win32_Neoreblamy_GPL_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {4d 70 41 56 49 76 6a 68 4f 69 49 4c 5a } //3 MpAVIvjhOiILZ
		$a_81_1 = {7a 48 6c 65 78 41 66 4c 42 4f 71 4e 7a 65 48 43 66 51 67 5a 62 } //2 zHlexAfLBOqNzeHCfQgZb
		$a_81_2 = {51 67 56 70 6b 4e 51 4e 55 53 57 56 4f 6c 53 74 73 53 6c 70 64 69 59 6e 4e } //1 QgVpkNQNUSWVOlStsSlpdiYnN
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=6
 
}