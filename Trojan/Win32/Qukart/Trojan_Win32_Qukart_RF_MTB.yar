
rule Trojan_Win32_Qukart_RF_MTB{
	meta:
		description = "Trojan:Win32/Qukart.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d ff ff 00 00 74 05 31 c0 40 eb 13 81 f7 17 01 00 00 83 c6 11 } //00 00 
	condition:
		any of ($a_*)
 
}