
rule Trojan_Win32_BypassUAC_AB_MTB{
	meta:
		description = "Trojan:Win32/BypassUAC.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d f8 21 38 95 93 2a 20 31 18 d5 1f 1e 38 31 34 81 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}