
rule Trojan_Win32_Emotet_DGB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 d3 03 c2 99 b9 90 01 04 f7 f9 8b 44 24 10 83 c0 01 89 44 24 10 8a 54 14 1c 30 50 ff 90 00 } //01 00 
		$a_81_1 = {44 6d 4e 30 7c 49 68 43 78 24 49 76 44 66 45 53 51 78 74 59 6f 31 25 4e 71 36 72 65 31 7c 24 } //00 00 
	condition:
		any of ($a_*)
 
}