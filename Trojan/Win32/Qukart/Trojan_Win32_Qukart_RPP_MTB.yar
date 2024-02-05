
rule Trojan_Win32_Qukart_RPP_MTB{
	meta:
		description = "Trojan:Win32/Qukart.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {31 08 90 90 90 90 90 83 c0 04 90 90 90 90 90 39 d8 90 90 90 90 75 e9 } //01 00 
		$a_01_1 = {90 89 c8 90 90 90 f7 f7 90 91 90 90 90 90 90 90 90 90 58 } //00 00 
	condition:
		any of ($a_*)
 
}