
rule Trojan_Win32_Tnega_CC_MTB{
	meta:
		description = "Trojan:Win32/Tnega.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {f6 5e 5e d3 2a f2 d2 45 00 } //00 00 
	condition:
		any of ($a_*)
 
}