
rule Trojan_Win32_Bladabindi_RPL_MTB{
	meta:
		description = "Trojan:Win32/Bladabindi.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {39 d2 74 01 ?? 31 32 81 c3 ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 81 c2 04 00 00 00 81 c3 ?? ?? ?? ?? 39 ca 75 dd c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}