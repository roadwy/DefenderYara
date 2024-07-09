
rule Trojan_Win32_Injector_RPH_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e8 24 00 00 00 31 13 [0-10] 81 c3 01 00 00 00 [0-10] 39 c3 75 da } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}