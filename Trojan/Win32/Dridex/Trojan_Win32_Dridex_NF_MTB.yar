
rule Trojan_Win32_Dridex_NF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 33 90 02 06 c7 05 90 02 08 8b 90 02 06 01 90 02 06 8b 90 02 06 8b 90 02 06 89 90 02 06 8b 90 02 06 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}