
rule Trojan_Win32_Zusy_RD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 65 00 88 07 00 e0 0f b6 f8 8b 44 24 14 8a 00 43 32 04 37 8b 3c 24 ff 44 24 14 47 88 43 ff } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_RD_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 74 72 62 79 74 6e 75 79 6b 69 2e 64 6c 6c 00 74 72 62 64 79 74 6a 75 6e 00 64 74 72 62 79 74 6e 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_RD_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c0 b9 82 00 00 00 bf b0 79 44 01 68 2b 03 00 00 f3 ab e8 0b f6 ff ff 8b 0d e0 a4 65 00 03 c8 83 c4 04 89 0d e0 a4 65 00 e8 65 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}