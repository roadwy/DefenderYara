
rule Trojan_Win32_Emotet_DSC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 8c 0d 90 01 04 0f b6 c3 03 c1 99 b9 90 01 04 f7 f9 8b 85 90 01 04 8a 8c 15 90 01 04 30 08 90 00 } //1
		$a_81_1 = {70 61 53 62 33 37 57 72 70 54 73 33 62 30 68 6d 6e 4f 43 69 7a 39 70 63 48 62 59 7a 50 58 64 42 70 4f 70 34 71 6c 36 67 6b } //1 paSb37WrpTs3b0hmnOCiz9pcHbYzPXdBpOp4ql6gk
		$a_81_2 = {65 75 66 4e 61 56 52 32 77 59 4d 39 50 30 74 54 47 36 70 48 49 58 48 4f 72 67 4d 76 6d 38 77 52 70 4b 59 37 62 7a 74 54 } //1 eufNaVR2wYM9P0tTG6pHIXHOrgMvm8wRpKY7bztT
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}