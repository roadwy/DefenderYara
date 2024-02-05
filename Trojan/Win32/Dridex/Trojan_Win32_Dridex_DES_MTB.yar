
rule Trojan_Win32_Dridex_DES_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 55 fc 83 ea 51 2b 15 90 01 04 89 15 90 01 04 a1 90 01 04 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 03 4d f8 8b 15 90 01 04 89 91 90 01 04 8b 45 fc 03 05 90 01 04 03 45 fc a3 90 01 04 b9 01 00 00 00 6b d1 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}