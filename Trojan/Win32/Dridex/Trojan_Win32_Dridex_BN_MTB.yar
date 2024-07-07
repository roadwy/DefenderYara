
rule Trojan_Win32_Dridex_BN_MTB{
	meta:
		description = "Trojan:Win32/Dridex.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b f0 2b f3 83 ee 07 8b d6 0f af d0 2b d3 0f af d1 2b d3 8d 42 1c 02 c3 00 44 24 0f } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}