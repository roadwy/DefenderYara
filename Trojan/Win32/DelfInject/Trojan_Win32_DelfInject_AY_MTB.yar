
rule Trojan_Win32_DelfInject_AY_MTB{
	meta:
		description = "Trojan:Win32/DelfInject.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 33 32 c4 32 07 88 07 47 4b } //00 00 
	condition:
		any of ($a_*)
 
}