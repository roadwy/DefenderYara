
rule Trojan_Win64_Emotet_PDA_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {ba 4e 00 00 00 33 c9 41 b9 13 03 00 00 41 b8 dd 03 00 00 ff 15 90 01 04 33 d2 48 8b c7 49 f7 f4 48 83 c7 01 0f b6 44 55 00 30 44 37 ff 48 3b fb 75 90 00 } //01 00 
		$a_81_1 = {43 73 57 78 66 38 39 6f 63 73 53 45 35 64 53 66 52 74 71 4c 65 46 32 75 4b 4a 31 59 65 64 6a 4c 74 } //00 00 
	condition:
		any of ($a_*)
 
}