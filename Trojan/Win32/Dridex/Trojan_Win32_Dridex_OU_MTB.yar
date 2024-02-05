
rule Trojan_Win32_Dridex_OU_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 08 5b 8b e5 5d c3 90 09 21 00 33 1d 90 02 04 c7 05 90 02 08 01 90 02 05 a1 90 02 04 8b 0d 90 00 } //01 00 
		$a_02_1 = {55 8b ec 51 53 eb 00 a1 90 02 04 a3 90 02 04 8b 0d 90 02 04 8b 11 89 15 90 02 04 8b 0d 90 02 04 a1 90 02 04 a3 90 02 04 8b 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}