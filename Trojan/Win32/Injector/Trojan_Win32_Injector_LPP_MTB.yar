
rule Trojan_Win32_Injector_LPP_MTB{
	meta:
		description = "Trojan:Win32/Injector.LPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 bc b6 9c 33 bc b6 9c 33 bc b6 9c 5c a3 bc 9c 37 bc b6 9c 5c a3 b2 9c 31 bc b6 9c 33 bc b7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}