
rule Trojan_Win32_Emotet_DHJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 3e 46 3b f3 7c c2 90 09 31 00 69 c0 90 01 04 68 90 01 0b 05 90 01 04 6a 00 a3 90 01 12 a0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}