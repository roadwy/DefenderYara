
rule Backdoor_BAT_Remcos_SM_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 05 11 0a 8f 11 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd } //02 00 
		$a_81_1 = {57 4e 48 42 4e 4d 4b 4c 2e 65 78 65 } //00 00  WNHBNMKL.exe
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Remcos_SM_MTB_2{
	meta:
		description = "Backdoor:BAT/Remcos.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {20 00 01 00 00 13 11 11 08 17 58 13 17 11 08 11 0e 5d 13 12 11 17 11 0e 5d 13 18 11 0d 11 18 91 11 11 58 13 19 11 0d 11 12 91 13 1a 11 1a 11 13 11 08 1f 16 5d 91 61 13 1b 11 1b 11 19 59 13 1c 11 0d 11 12 11 1c 11 11 5d d2 9c 11 08 17 58 13 08 11 08 11 0e 11 14 17 58 5a fe 04 13 1d 11 1d 2d 9e } //00 00 
	condition:
		any of ($a_*)
 
}