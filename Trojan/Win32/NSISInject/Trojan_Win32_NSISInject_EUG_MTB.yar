
rule Trojan_Win32_NSISInject_EUG_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.EUG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d8 59 59 6a 04 68 00 30 00 00 68 90 01 04 57 ff d6 90 00 } //01 00 
		$a_03_1 = {53 6a 01 bb 90 01 04 8b f0 53 56 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}