
rule Trojan_Win64_ShellcodeInject_MP_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 15 71 da 00 00 33 c9 8b f8 ff 15 2f da 00 00 48 8d 4c 24 48 ff 15 cc db 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}