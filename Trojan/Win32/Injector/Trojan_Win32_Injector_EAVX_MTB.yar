
rule Trojan_Win32_Injector_EAVX_MTB{
	meta:
		description = "Trojan:Win32/Injector.EAVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 4e fb 33 c0 8d 49 00 8a 14 06 8b d8 32 d1 d1 eb 83 c0 02 88 94 1c 20 02 00 00 3d 70 17 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}