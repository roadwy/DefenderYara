
rule Trojan_Win32_Emotet_PEK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 d2 03 d3 81 e2 90 01 04 79 90 01 01 4a 81 ca 00 ff ff ff 42 0f b6 54 14 90 01 01 32 14 0f 41 83 ed 01 88 51 90 00 } //01 00 
		$a_81_1 = {5a 57 46 4b 25 70 40 57 75 7d 57 41 7b 62 43 50 45 39 68 58 54 3f 47 58 51 4c 4b 77 46 } //00 00  ZWFK%p@Wu}WA{bCPE9hXT?GXQLKwF
	condition:
		any of ($a_*)
 
}