
rule Trojan_Win32_SmokeLoader_MIU_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.MIU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 89 45 90 01 01 8d 45 90 01 01 50 e8 90 01 04 52 8d 45 90 01 01 50 e8 90 01 04 8b 45 90 01 01 33 45 90 01 01 83 65 90 01 02 2b f8 8b 45 90 01 01 01 45 90 01 01 29 45 90 01 01 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}