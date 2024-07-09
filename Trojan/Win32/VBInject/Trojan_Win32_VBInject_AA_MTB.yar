
rule Trojan_Win32_VBInject_AA_MTB{
	meta:
		description = "Trojan:Win32/VBInject.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 0f eb 01 ?? eb 01 ?? 6a 00 eb 01 ?? eb 01 ?? 89 0c 24 eb 01 ?? eb 01 ?? 31 34 24 eb 01 ?? eb 01 ?? 59 eb 01 ?? eb 01 ?? e8 35 00 00 00 eb 01 } //1
		$a_02_1 = {8f 04 18 eb 01 ?? eb 01 ?? c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}