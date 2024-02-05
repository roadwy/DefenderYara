
rule Trojan_Win32_SmokeLoader_UY_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.UY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ae 00 c6 c6 c6 90 01 01 2d 90 01 04 32 d7 2e 20 38 39 39 5f 90 0a 28 00 e5 90 01 01 a2 90 01 04 02 c2 2d 90 01 04 34 90 01 01 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}