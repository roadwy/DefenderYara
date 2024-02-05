
rule Trojan_Win32_Dridex_PL_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 ca 83 e2 90 01 01 88 90 02 03 8b 90 02 03 8a 90 02 02 2a 90 02 06 04 20 8b 90 02 03 88 90 02 02 83 90 02 03 89 90 02 03 8b 90 02 03 39 f9 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}