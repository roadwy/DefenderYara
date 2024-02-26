
rule Trojan_Win64_BlisterLoader_SA_MTB{
	meta:
		description = "Trojan:Win64/BlisterLoader.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 c0 4d 8d 49 90 01 01 41 33 c0 44 69 c0 90 01 04 41 8b c0 c1 e8 90 01 01 44 33 c0 41 90 01 03 66 90 01 02 75 90 01 01 41 90 01 06 74 90 00 } //01 00 
		$a_03_1 = {0f be c0 49 03 cc 41 33 c1 44 90 01 06 41 8b c1 c1 e8 90 01 01 44 33 c8 8a 01 84 c0 75 90 01 01 41 90 01 06 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}