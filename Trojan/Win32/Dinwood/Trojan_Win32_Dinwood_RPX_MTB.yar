
rule Trojan_Win32_Dinwood_RPX_MTB{
	meta:
		description = "Trojan:Win32/Dinwood.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 80 37 18 83 c7 04 6a 05 59 ad 31 07 83 c7 04 e2 f8 } //00 00 
	condition:
		any of ($a_*)
 
}