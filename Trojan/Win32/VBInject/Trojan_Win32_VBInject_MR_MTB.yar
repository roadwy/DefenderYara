
rule Trojan_Win32_VBInject_MR_MTB{
	meta:
		description = "Trojan:Win32/VBInject.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 d1 83 f8 90 02 08 90 18 81 90 02 05 01 90 01 01 83 90 02 02 3d 90 02 04 8b 90 01 01 3d 90 02 04 83 90 02 02 90 18 81 90 02 05 81 90 02 05 3d 90 02 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}