
rule Trojan_Win32_Dridex_PF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 55 f8 83 90 02 02 89 90 02 02 81 90 02 06 0f 90 02 05 0f 90 02 06 8b 90 02 05 8d 90 02 03 89 90 02 05 a1 90 02 04 03 90 02 02 8b 90 02 05 89 90 02 05 69 90 02 09 0f 90 02 03 03 90 01 01 66 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}