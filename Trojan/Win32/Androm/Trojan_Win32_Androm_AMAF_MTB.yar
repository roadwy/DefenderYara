
rule Trojan_Win32_Androm_AMAF_MTB{
	meta:
		description = "Trojan:Win32/Androm.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 31 45 fc 33 55 fc 89 55 d0 8b 45 d0 } //00 00 
	condition:
		any of ($a_*)
 
}