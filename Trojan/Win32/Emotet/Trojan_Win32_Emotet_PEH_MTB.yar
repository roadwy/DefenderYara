
rule Trojan_Win32_Emotet_PEH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 90 01 04 99 f7 f9 8b 8c 24 90 01 04 8a 84 14 90 01 04 8b 54 24 90 01 01 32 04 0a 88 44 24 90 00 } //01 00 
		$a_81_1 = {46 47 4d 51 56 44 46 39 53 75 72 46 6a 50 4a 46 68 4e 54 46 59 63 6d 50 71 56 37 77 62 48 36 57 30 33 74 4b 7a 69 44 44 63 45 57 42 56 } //00 00  FGMQVDF9SurFjPJFhNTFYcmPqV7wbH6W03tKziDDcEWBV
	condition:
		any of ($a_*)
 
}