
rule Trojan_Win64_IcedID_MQ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {44 0f af 46 54 2d ab 9f 01 00 09 46 04 48 8b 86 c0 00 00 00 41 8b d0 c1 ea 08 88 14 01 ff 46 60 8b 86 e8 00 00 00 48 63 4e 60 2d 93 ab 18 00 01 86 90 00 00 00 48 8b 86 c0 00 00 00 44 88 04 01 ff 46 60 8b 86 ec 00 00 00 ff c8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MQ_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } //01 00  PluginInit
		$a_01_1 = {6c 43 71 42 64 65 7a 35 76 75 2e 64 6c 6c } //01 00  lCqBdez5vu.dll
		$a_01_2 = {42 58 64 41 69 78 43 6d 4b 53 } //01 00  BXdAixCmKS
		$a_01_3 = {48 79 4f 72 56 51 52 57 61 49 } //01 00  HyOrVQRWaI
		$a_01_4 = {50 59 44 45 6b 6e 4f 6d 71 4e } //01 00  PYDEknOmqN
		$a_01_5 = {54 77 5a 48 58 52 6a 55 6f 75 46 } //00 00  TwZHXRjUouF
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_MQ_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {61 69 73 75 6b 66 6a 6e 75 61 73 68 66 6b 61 73 69 6a 66 75 68 61 6b 73 6a 75 64 68 69 6b 6a } //05 00  aisukfjnuashfkasijfuhaksjudhikj
		$a_01_1 = {44 37 38 36 32 35 64 39 65 35 66 63 62 34 65 36 39 32 63 38 62 66 34 39 33 33 64 37 31 66 39 39 } //05 00  D78625d9e5fcb4e692c8bf4933d71f99
		$a_01_2 = {34 37 39 38 34 37 32 64 32 30 64 62 30 35 30 35 30 34 38 38 34 38 62 35 35 36 31 38 61 62 35 39 } //01 00  4798472d20db0505048848b55618ab59
		$a_01_3 = {44 75 70 6c 69 63 61 74 65 48 61 6e 64 6c 65 } //01 00  DuplicateHandle
		$a_01_4 = {45 6e 75 6d 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 } //01 00  EnumResourceNames
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_6 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //00 00  GetCurrentProcess
	condition:
		any of ($a_*)
 
}