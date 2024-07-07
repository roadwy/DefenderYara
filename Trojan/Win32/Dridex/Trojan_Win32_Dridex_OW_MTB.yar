
rule Trojan_Win32_Dridex_OW_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 08 5b 8b e5 5d c3 90 09 23 00 8b 90 02 05 33 90 01 01 c7 05 90 02 08 01 90 02 05 a1 90 02 04 8b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}