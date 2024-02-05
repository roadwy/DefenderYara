
rule Trojan_Win32_SmokeLoader_MJO_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.MJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 90 01 01 03 45 90 01 01 8d 0c 33 33 c1 33 45 90 01 01 81 c3 90 01 04 2b f8 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}