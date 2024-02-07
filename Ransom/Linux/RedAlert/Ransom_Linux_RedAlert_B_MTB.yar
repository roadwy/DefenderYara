
rule Ransom_Linux_RedAlert_B_MTB{
	meta:
		description = "Ransom:Linux/RedAlert.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 20 4e 31 33 56 20 } //01 00  [ N13V 
		$a_01_1 = {2f 68 6f 6d 65 2f 61 31 33 78 2f 44 6f 63 75 6d 65 6e 74 73 2f 50 4a 2f 6d 61 69 6e 32 6e 69 78 2f 43 4c 69 6f 6e 50 72 6f 6a 65 63 74 73 2f 6e 74 72 75 5f 63 6f 64 65 } //01 00  /home/a13x/Documents/PJ/main2nix/CLionProjects/ntru_code
		$a_01_2 = {65 6e 63 2e 66 69 6c 65 } //01 00  enc.file
		$a_01_3 = {2e 76 6d 64 6b } //00 00  .vmdk
	condition:
		any of ($a_*)
 
}