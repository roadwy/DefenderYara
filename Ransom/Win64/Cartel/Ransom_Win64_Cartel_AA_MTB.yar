
rule Ransom_Win64_Cartel_AA_MTB{
	meta:
		description = "Ransom:Win64/Cartel.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 4c 24 90 01 01 48 8b 54 24 90 01 01 0f b6 0c 0a 03 c1 0f b6 4c 24 90 01 01 03 c1 25 ff 00 00 00 88 44 24 90 01 01 0f b7 44 24 90 01 01 48 8b 4c 24 90 01 01 0f b6 04 01 88 44 24 90 01 01 0f b6 44 24 90 01 01 0f b7 4c 24 90 01 01 48 8b 54 24 90 01 01 4c 8b 44 24 90 01 01 41 0f b6 04 00 88 04 0a 90 00 } //01 00 
		$a_01_1 = {2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 00 } //00 00  /c vssadmin.exe Delete Shadows /All /Quiet
	condition:
		any of ($a_*)
 
}