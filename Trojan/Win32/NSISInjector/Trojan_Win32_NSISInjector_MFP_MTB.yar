
rule Trojan_Win32_NSISInjector_MFP_MTB{
	meta:
		description = "Trojan:Win32/NSISInjector.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {b2 bc ff 79 b2 bc ff 79 b2 bc ff 79 b2 bc ff } //1
		$a_01_1 = {79 b2 bc 0f 79 } //1
		$a_01_2 = {b2 bc ff 78 b2 bc ff 78 b2 bc ff 78 b2 bc ff 78 b2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}