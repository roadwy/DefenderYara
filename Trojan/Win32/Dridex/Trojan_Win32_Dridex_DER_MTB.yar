
rule Trojan_Win32_Dridex_DER_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c6 8d 04 83 89 44 24 1c 66 a3 90 01 04 8b 7c 24 18 8b 44 24 10 05 90 01 04 89 44 24 10 89 07 6b fb 1d a3 90 01 04 0f b7 05 90 01 04 83 c7 09 03 f9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}