
rule Trojan_Win32_Emotet_DEN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 90 01 04 99 f7 f9 8a 03 8a 54 14 1c 32 c2 88 03 90 00 } //01 00 
		$a_81_1 = {35 30 67 54 47 73 34 70 6c 4c 49 34 44 66 45 34 6c 4f 6e 43 59 58 76 65 39 6d 53 5a 5a 39 65 57 4a } //00 00  50gTGs4plLI4DfE4lOnCYXve9mSZZ9eWJ
	condition:
		any of ($a_*)
 
}