
rule Trojan_Win32_SmokeLoader_XIM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.XIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e0 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 83 0d 90 01 05 8b c6 c1 e8 90 01 01 03 45 90 01 01 03 de 33 d8 31 5d 90 01 01 2b 7d 90 01 01 68 90 01 04 8d 45 90 01 01 50 c7 05 90 01 08 e8 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}