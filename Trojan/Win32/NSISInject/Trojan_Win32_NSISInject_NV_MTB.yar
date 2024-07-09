
rule Trojan_Win32_NSISInject_NV_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b f8 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 56 ff 15 ?? 20 40 00 } //1
		$a_03_1 = {57 6a 01 8b d8 68 ?? ?? ?? ?? 53 ff 15 ?? 20 40 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}