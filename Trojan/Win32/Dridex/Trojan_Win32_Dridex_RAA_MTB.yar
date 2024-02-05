
rule Trojan_Win32_Dridex_RAA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 04 8b 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 03 15 90 01 04 2b 55 90 01 01 03 15 90 01 04 89 15 90 01 04 a1 90 01 04 2b 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 03 0d 90 01 04 89 0d 90 01 04 83 3d 90 01 04 00 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}