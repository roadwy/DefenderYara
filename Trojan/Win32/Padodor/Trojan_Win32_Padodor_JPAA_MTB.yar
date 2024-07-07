
rule Trojan_Win32_Padodor_JPAA_MTB{
	meta:
		description = "Trojan:Win32/Padodor.JPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d8 01 d8 89 c3 81 eb e4 34 00 00 81 eb 3f 7a 00 00 89 d8 29 d8 89 c3 f7 e3 89 85 90 01 04 89 c3 81 f3 1b 6a 00 00 89 d8 f7 e3 89 85 90 01 04 89 c3 f7 e3 89 85 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}