
rule Trojan_Win32_SmokeLoader_IW_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.IW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 c7 05 90 01 08 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 83 65 90 01 02 8b c6 c1 e0 90 01 01 03 45 90 01 01 33 45 90 01 01 33 c1 2b f8 8b 45 90 01 01 01 45 90 01 01 29 45 90 01 01 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}