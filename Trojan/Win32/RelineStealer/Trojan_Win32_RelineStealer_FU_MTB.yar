
rule Trojan_Win32_RelineStealer_FU_MTB{
	meta:
		description = "Trojan:Win32/RelineStealer.FU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 95 64 fd ff ff 03 55 a4 89 95 90 01 04 8b 85 90 01 04 0f af 85 90 01 04 89 85 90 01 04 8b 8d 90 01 04 0f af 4d a8 89 4d b0 8b 95 90 01 04 0f af 95 90 01 04 89 55 94 8b 85 90 01 04 3b 85 d0 fe ff ff 90 00 } //0a 00 
		$a_02_1 = {8b 45 08 83 c0 61 89 85 90 01 04 8b 4d 08 83 c1 09 89 8d 90 01 04 8b 55 08 83 c2 3f 89 95 90 01 04 8b 85 90 01 04 3b 85 10 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}