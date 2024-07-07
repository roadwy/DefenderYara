
rule Trojan_Win32_Fariet_KR_MTB{
	meta:
		description = "Trojan:Win32/Fariet.KR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff 33 d2 89 90 01 04 00 33 c0 a3 88 bb 46 00 e8 f6 32 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}