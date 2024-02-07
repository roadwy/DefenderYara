
rule Trojan_Win64_Emotet_EB_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {49 2b c1 4c 63 c2 4d 6b c0 15 4c 03 c0 48 8b 44 24 28 41 8a 0c 08 41 32 0c 02 43 88 0c 1a 49 83 c2 01 44 3b 64 24 20 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_EB_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8a 04 01 41 32 04 29 41 88 01 49 ff c1 45 3b c4 72 c4 49 8b c3 48 8b 5c 24 30 48 8b 6c 24 38 48 8b 74 24 40 48 8b 7c 24 48 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_EB_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8a 04 08 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72 c7 49 8b c1 48 8b 5c 24 50 48 8b 6c 24 58 48 8b 74 24 60 48 8b 7c 24 68 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_EB_MTB_4{
	meta:
		description = "Trojan:Win64/Emotet.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 54 53 63 72 61 74 63 68 70 61 64 52 54 53 74 79 6c 75 73 2e 64 6c 6c } //01 00  MTScratchpadRTStylus.dll
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_2 = {50 6f 73 74 51 75 69 74 4d 65 73 73 61 67 65 } //01 00  PostQuitMessage
		$a_01_3 = {43 72 79 70 74 53 74 72 69 6e 67 54 6f 42 69 6e 61 72 79 41 } //01 00  CryptStringToBinaryA
		$a_01_4 = {52 74 6c 4c 6f 6f 6b 75 70 46 75 6e 63 74 69 6f 6e 45 6e 74 72 79 } //00 00  RtlLookupFunctionEntry
	condition:
		any of ($a_*)
 
}