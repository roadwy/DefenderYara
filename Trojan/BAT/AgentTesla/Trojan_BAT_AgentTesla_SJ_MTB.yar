
rule Trojan_BAT_AgentTesla_SJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 08 17 58 13 06 07 08 07 08 91 28 15 00 00 06 08 1f 16 5d 91 61 07 11 06 09 5d 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 08 17 58 0c 00 08 09 fe 04 13 07 11 07 2d c6 } //2
		$a_81_1 = {46 6f 6c 64 65 72 53 65 61 72 63 68 65 72 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //2 FolderSearcher.Form1.resources
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AgentTesla_SJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {00 08 02 6f 19 00 00 0a fe 04 16 fe 01 13 12 11 12 2c 05 38 f7 01 00 00 09 02 6f 1a 00 00 0a fe 04 16 fe 01 13 13 11 13 2c 05 } //1
		$a_00_1 = {06 11 0d 18 91 6f 1e 00 00 0a 00 11 05 17 59 25 13 05 16 fe 02 16 fe 01 13 17 11 17 2c 05 38 a8 00 00 00 06 } //1
		$a_81_2 = {55 6e 72 61 76 65 6c 47 72 61 70 68 69 63 4d 61 74 72 69 78 } //1 UnravelGraphicMatrix
		$a_81_3 = {64 69 63 65 67 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 dicegame.Properties.Resources
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_BAT_AgentTesla_SJ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 38 07 01 00 00 00 02 08 09 6f 47 00 00 0a 13 05 19 8d 4c 00 00 01 25 16 12 05 28 38 00 00 0a 9c 25 17 12 05 28 3a 00 00 0a 9c 25 18 12 05 28 3b 00 00 0a 9c 7e 73 00 00 04 25 2d 17 26 7e 6e 00 00 04 fe 06 93 00 00 06 73 48 00 00 0a 25 } //1
		$a_81_1 = {54 72 61 79 4f 72 67 61 6e 69 7a 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 TrayOrganizer.Properties.Resources.resources
		$a_81_2 = {24 61 35 62 38 63 39 64 31 2d 32 65 33 66 2d 34 61 35 62 2d 38 63 39 64 2d 31 65 32 66 33 61 34 62 35 63 36 64 } //1 $a5b8c9d1-2e3f-4a5b-8c9d-1e2f3a4b5c6d
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_SJ_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.SJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 03 04 00 06 fe 0e 00 00 16 fe 0e 03 00 fe 0c 03 00 17 5a fe 0e 04 00 03 28 0b 02 00 0a fe 0e 01 00 00 00 fe 0c 00 00 8e 69 17 59 fe 0e 02 00 2b 2e fe 0c 00 00 fe 0c 02 00 fe 0c 00 00 fe 0c 02 00 91 fe 0c 01 00 fe 0c 02 00 fe 0c 01 00 8e 69 5d 91 61 d2 9c fe 0c 02 00 17 59 fe 0e 02 00 fe 0c 02 00 16 2f cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}