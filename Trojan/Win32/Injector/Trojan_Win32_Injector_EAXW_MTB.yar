
rule Trojan_Win32_Injector_EAXW_MTB{
	meta:
		description = "Trojan:Win32/Injector.EAXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 14 06 8b d8 32 d1 d1 eb 83 c0 02 88 94 1c 20 02 00 00 3d 70 17 00 00 72 e6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}