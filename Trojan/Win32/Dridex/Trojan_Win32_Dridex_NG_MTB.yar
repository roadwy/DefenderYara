
rule Trojan_Win32_Dridex_NG_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {eb 00 eb 00 8b 90 02 06 33 90 02 03 c7 05 90 02 08 8b 90 02 03 01 90 02 06 a1 90 02 04 8b 0d 90 02 04 89 90 02 03 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}