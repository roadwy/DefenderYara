
rule Backdoor_Win64_Bazdor_B_MTB{
	meta:
		description = "Backdoor:Win64/Bazdor.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {48 83 ec 20 48 89 6c 24 18 48 8d 6c 24 18 65 48 8b 0c 25 28 00 00 00 bb 00 00 00 00 48 83 f9 00 74 07 48 8b 99 00 00 00 00 48 83 fb 00 74 0b 48 8b 5b 30 48 89 5c 24 10 eb 2d } //03 00 
		$a_80_1 = {5f 63 67 6f 5f 64 75 6d 6d 79 5f 65 78 70 6f 72 74 } //_cgo_dummy_export  03 00 
		$a_80_2 = {61 65 78 6a 6e 6e 6a 79 79 61 71 64 6f 61 } //aexjnnjyyaqdoa  03 00 
		$a_80_3 = {63 64 61 63 6f 65 75 6e 65 6e 65 6d 67 } //cdacoeunenemg  03 00 
		$a_80_4 = {63 62 64 6a 76 78 72 70 6f 69 76 78 77 66 72 76 61 6a 68 2e } //cbdjvxrpoivxwfrvajh.  00 00 
	condition:
		any of ($a_*)
 
}