
rule Trojan_Win32_NSISInjector_MFP_MTB{
	meta:
		description = "Trojan:Win32/NSISInjector.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {b2 bc ff 79 b2 bc ff 79 b2 bc ff 79 b2 bc ff } //01 00 
		$a_01_1 = {79 b2 bc 0f 79 } //01 00 
		$a_01_2 = {b2 bc ff 78 b2 bc ff 78 b2 bc ff 78 b2 bc ff 78 b2 } //00 00 
	condition:
		any of ($a_*)
 
}