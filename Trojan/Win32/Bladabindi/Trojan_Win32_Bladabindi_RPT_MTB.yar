
rule Trojan_Win32_Bladabindi_RPT_MTB{
	meta:
		description = "Trojan:Win32/Bladabindi.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 1e 21 d2 21 d2 81 c6 04 00 00 00 ba 90 01 04 4f 39 ce 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}