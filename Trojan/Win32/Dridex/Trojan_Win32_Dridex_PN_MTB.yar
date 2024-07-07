
rule Trojan_Win32_Dridex_PN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 c1 41 89 90 01 01 83 90 01 02 89 90 01 03 89 90 01 03 89 90 01 03 0f 84 90 01 04 90 18 8b 90 01 03 83 90 01 02 8b 90 01 03 89 90 01 03 89 90 01 03 0f 84 90 01 04 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}