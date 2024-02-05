
rule Trojan_Win32_SmokeLoader_KWL_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.KWL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 90 01 01 03 45 90 01 01 03 de 33 c3 33 45 90 01 01 50 8d 45 90 01 01 50 e8 90 01 04 68 90 01 04 8d 45 90 01 01 50 e8 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}