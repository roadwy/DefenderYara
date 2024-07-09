
rule Trojan_Win32_VBInject_CZ_MTB{
	meta:
		description = "Trojan:Win32/VBInject.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b f2 3b f1 72 ?? ff ?? eb ?? ff ?? 8b f0 8b 45 08 8b 08 8b 85 10 ff ff ff 8b 51 0c 66 0f b6 0c 02 8b 55 b4 66 33 0c 7a ff 15 ?? ?? ?? ?? 8b 4d 08 8b 11 8b 4a 0c 88 04 31 8b 4d cc b8 01 00 00 00 03 c1 70 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}