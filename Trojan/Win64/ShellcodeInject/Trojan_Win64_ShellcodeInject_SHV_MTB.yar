
rule Trojan_Win64_ShellcodeInject_SHV_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.SHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 28 8c 04 f0 00 00 00 0f 57 c8 0f 28 94 04 00 01 00 00 0f 57 d0 0f 29 8c 04 f0 00 00 00 0f 29 94 04 00 01 00 00 0f 28 8c 04 10 01 00 00 0f 57 c8 0f 28 94 04 20 01 00 00 0f 57 d0 0f 29 8c 04 10 01 00 00 0f 29 94 04 20 01 00 00 48 83 c0 40 48 3d b0 03 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}