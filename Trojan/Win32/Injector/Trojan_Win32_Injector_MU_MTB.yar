
rule Trojan_Win32_Injector_MU_MTB{
	meta:
		description = "Trojan:Win32/Injector.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 0f 58 c1 [0-20] 66 0f 6e e6 [0-10] 66 0f 6e e9 [0-0a] 0f 57 ec [0-10] 66 0f 7e e9 [0-15] 39 c1 [0-20] 90 13 0f 77 [0-10] 46 [0-10] 8b 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}