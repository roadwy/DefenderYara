
rule Trojan_Win32_Doina_RPX_MTB{
	meta:
		description = "Trojan:Win32/Doina.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff ff ff ff 10 6a 40 68 00 10 00 00 68 90 01 03 00 6a 00 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}