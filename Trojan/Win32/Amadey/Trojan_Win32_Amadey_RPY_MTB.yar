
rule Trojan_Win32_Amadey_RPY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {1d b0 00 00 00 f7 ee 81 ce b8 00 00 00 33 c9 33 ff 48 83 de 09 25 e0 00 00 00 f7 d0 c1 ca e9 81 df e0 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}