
rule Trojan_Win32_Qukart_RPO_MTB{
	meta:
		description = "Trojan:Win32/Qukart.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {90 31 30 90 90 90 90 90 90 01 f8 90 90 90 90 e2 ef } //01 00 
		$a_01_1 = {89 c8 90 90 90 90 90 90 f7 f7 90 90 90 91 90 90 90 } //00 00 
	condition:
		any of ($a_*)
 
}