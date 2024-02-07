
rule Trojan_BAT_Zbot_B_MTB{
	meta:
		description = "Trojan:BAT/Zbot.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {74 68 69 61 67 6f 2e 72 63 6c 61 72 6f 5c 44 72 6f 70 62 6f 78 5c 50 72 6f 6a 65 74 6f 73 5c 42 6f 64 65 4f 66 57 61 72 5c 42 6f 64 65 4f 66 57 61 72 43 6c 69 65 6e 74 5c 42 6f 64 65 4f 66 57 61 72 43 6c 69 65 6e 74 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 43 61 6e 74 53 74 6f 70 43 6c 69 65 6e 74 2e 70 64 62 } //01 00  thiago.rclaro\Dropbox\Projetos\BodeOfWar\BodeOfWarClient\BodeOfWarClient\obj\x86\Debug\CantStopClient.pdb
		$a_81_1 = {43 61 72 74 61 67 65 6e 61 43 6c 69 65 6e 74 } //01 00  CartagenaClient
		$a_81_2 = {24 30 36 61 32 38 36 61 38 2d 36 33 30 61 2d 34 64 33 37 2d 38 36 65 62 2d 63 37 64 61 32 32 32 32 30 36 36 37 } //00 00  $06a286a8-630a-4d37-86eb-c7da22220667
	condition:
		any of ($a_*)
 
}