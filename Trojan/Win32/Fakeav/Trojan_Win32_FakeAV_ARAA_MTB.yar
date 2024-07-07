
rule Trojan_Win32_FakeAV_ARAA_MTB{
	meta:
		description = "Trojan:Win32/FakeAV.ARAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 f9 00 74 0a 8a 06 32 c3 88 06 46 49 eb f1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}