
rule Trojan_Win32_Mokes_AMCC_MTB{
	meta:
		description = "Trojan:Win32/Mokes.AMCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 31 45 fc 33 55 fc 89 55 d8 8b 45 d8 } //00 00 
	condition:
		any of ($a_*)
 
}