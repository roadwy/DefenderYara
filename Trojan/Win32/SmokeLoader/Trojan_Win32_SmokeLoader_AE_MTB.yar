
rule Trojan_Win32_SmokeLoader_AE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {03 c1 83 e0 03 0f b6 80 90 02 04 30 81 90 02 04 83 c1 04 81 f9 00 76 00 00 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}