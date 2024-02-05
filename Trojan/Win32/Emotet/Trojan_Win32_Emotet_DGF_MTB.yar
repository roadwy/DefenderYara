
rule Trojan_Win32_Emotet_DGF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {0f b6 c9 03 c1 99 b9 30 2a 01 00 f7 f9 8a 5c 14 1c 32 5d 00 } //01 00 
		$a_81_1 = {74 73 6e 51 4d 57 44 73 30 62 58 51 78 4b 6b 58 73 36 68 49 47 61 76 4f 50 53 71 43 59 79 30 47 59 37 4e 47 65 } //00 00 
	condition:
		any of ($a_*)
 
}