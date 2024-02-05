
rule Backdoor_Win64_Havoc_D{
	meta:
		description = "Backdoor:Win64/Havoc.D,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_03_0 = {48 8b 1d ff 73 00 00 83 3d 50 60 00 00 90 01 01 75 0e e8 41 f9 ff ff 85 c0 74 05 e8 18 ee ff ff b9 90 01 02 00 00 ff d3 eb e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}