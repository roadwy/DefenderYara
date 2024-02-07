
rule Trojan_BAT_AgentTesla_NF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 ff b7 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 c7 00 00 00 78 07 00 00 07 08 00 00 ce 68 00 00 d7 } //01 00 
		$a_01_1 = {8a 00 00 cc 03 00 00 c8 01 00 00 8c 03 00 00 9d 0d 00 00 16 73 00 00 02 00 00 00 05 00 00 00 2c 00 00 00 e5 00 } //01 00 
		$a_01_2 = {38 41 38 44 30 42 42 34 38 35 45 31 } //00 00  8A8D0BB485E1
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NF_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 16 06 8e 69 28 90 01 03 0a 02 7b 90 01 03 04 25 2d 02 26 2a 06 7e 90 01 03 0a 6f 90 01 03 0a 2a 90 00 } //01 00 
		$a_01_1 = {6e 69 61 4d 6c 6c 44 72 6f 43 5f } //01 00  niaMllDroC_
		$a_01_2 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_3 = {2e 65 64 6f 6d 20 53 4f 44 20 6e 69 20 6e 75 72 20 65 62 20 74 6f 6e 6e 61 63 20 6d 61 72 67 6f 72 70 20 73 69 68 54 21 } //00 00  .edom SOD ni nur eb tonnac margorp sihT!
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NF_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 0a 00 00 05 00 "
		
	strings :
		$a_81_0 = {44 72 61 77 34 42 69 74 49 6d 61 67 65 } //05 00  Draw4BitImage
		$a_81_1 = {49 54 79 70 65 43 6f 6d 70 } //05 00  ITypeComp
		$a_81_2 = {67 65 74 5f 41 63 72 6f 73 73 50 61 72 74 69 74 69 6f 6e 73 } //05 00  get_AcrossPartitions
		$a_81_3 = {43 61 72 74 6f 6f 6e 65 72 73 46 69 6c 65 56 69 65 77 65 72 50 72 6f 67 72 61 6d 2e 53 65 31 } //05 00  CartoonersFileViewerProgram.Se1
		$a_81_4 = {43 61 72 74 6f 6f 6e 73 2e 65 78 65 } //01 00  Cartoons.exe
		$a_81_5 = {24 53 54 41 54 49 43 24 45 78 70 6f 72 74 46 69 6c 65 73 4d 65 6e 75 5f 43 6c 69 63 6b 24 32 30 32 31 31 43 31 32 38 30 41 31 24 50 61 74 68 4f } //01 00  $STATIC$ExportFilesMenu_Click$20211C1280A1$PathO
		$a_81_6 = {43 61 72 74 6f 6f 6e 65 72 73 46 69 6c 65 56 69 65 77 65 72 50 72 6f 67 72 61 6d 2e 52 65 73 6f 75 72 63 65 73 } //01 00  CartoonersFileViewerProgram.Resources
		$a_81_7 = {63 73 74 6f 6f 6e 2e 73 6d 62 } //01 00  cstoon.smb
		$a_81_8 = {47 42 52 54 6f 54 65 78 74 } //01 00  GBRToText
		$a_81_9 = {24 36 30 32 33 32 39 46 30 2d 43 35 41 46 2d 34 30 35 37 2d 38 43 36 36 2d 34 45 33 31 45 43 32 43 32 32 46 38 } //00 00  $602329F0-C5AF-4057-8C66-4E31EC2C22F8
	condition:
		any of ($a_*)
 
}