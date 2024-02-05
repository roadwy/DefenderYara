
rule Trojan_Win32_VBInject_AA_MTB{
	meta:
		description = "Trojan:Win32/VBInject.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 0f eb 01 90 01 01 eb 01 90 01 01 6a 00 eb 01 90 01 01 eb 01 90 01 01 89 0c 24 eb 01 90 01 01 eb 01 90 01 01 31 34 24 eb 01 90 01 01 eb 01 90 01 01 59 eb 01 90 01 01 eb 01 90 01 01 e8 35 00 00 00 eb 01 90 00 } //01 00 
		$a_02_1 = {8f 04 18 eb 01 90 01 01 eb 01 90 01 01 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}