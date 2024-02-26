
rule Trojan_Win32_Doina_RPY_MTB{
	meta:
		description = "Trojan:Win32/Doina.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 85 c0 74 0f 33 c0 50 50 50 50 50 e8 4a 00 00 00 83 c4 14 8b 45 fc 69 c0 } //00 00 
	condition:
		any of ($a_*)
 
}