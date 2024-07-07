
rule Trojan_Win32_Injector_MU_MTB{
	meta:
		description = "Trojan:Win32/Injector.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 0f 58 c1 90 02 20 66 0f 6e e6 90 02 10 66 0f 6e e9 90 02 0a 0f 57 ec 90 02 10 66 0f 7e e9 90 02 15 39 c1 90 02 20 90 13 0f 77 90 02 10 46 90 02 10 8b 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}