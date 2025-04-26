
rule Trojan_Win32_Injector_RTG_MTB{
	meta:
		description = "Trojan:Win32/Injector.RTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 45 ff 83 c0 13 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}