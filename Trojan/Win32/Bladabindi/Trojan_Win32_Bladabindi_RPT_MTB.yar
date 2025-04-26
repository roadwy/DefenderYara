
rule Trojan_Win32_Bladabindi_RPT_MTB{
	meta:
		description = "Trojan:Win32/Bladabindi.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 1e 21 d2 21 d2 81 c6 04 00 00 00 ba ?? ?? ?? ?? 4f 39 ce 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}