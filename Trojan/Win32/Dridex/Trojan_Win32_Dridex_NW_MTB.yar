
rule Trojan_Win32_Dridex_NW_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 10 39 90 02 03 90 18 8b 90 02 06 8b 90 02 03 8b 90 02 03 35 90 02 04 83 90 02 02 01 90 01 01 8a 90 02 02 88 90 02 03 8a 90 02 06 22 90 02 06 88 90 02 06 8b 90 02 03 89 90 02 02 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}