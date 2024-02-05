
rule Trojan_Win32_Qakbot_SF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 5c 24 28 81 e9 90 01 04 0f af 88 90 01 04 c1 eb 90 01 01 89 88 90 01 04 8b 48 90 01 01 8d 91 90 01 04 0b d1 89 50 90 00 } //01 00 
		$a_03_1 = {8b 48 68 81 f1 90 01 04 29 48 90 01 01 8b 88 90 01 04 09 88 90 01 04 8b 88 90 01 04 01 88 90 01 04 81 ff 90 01 04 0f 8c 90 00 } //01 00 
		$a_00_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}