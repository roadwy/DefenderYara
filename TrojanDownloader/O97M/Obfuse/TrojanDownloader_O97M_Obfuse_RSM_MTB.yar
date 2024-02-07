
rule TrojanDownloader_O97M_Obfuse_RSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 61 6e 67 65 28 22 41 31 3a 4a 31 35 22 29 2e 53 65 6c 65 63 74 } //01 00  Range("A1:J15").Select
		$a_00_1 = {74 61 64 6c 62 6e 74 71 66 6c 71 74 62 74 70 65 65 6f 69 64 6a 7a 6a 64 6e 6e 78 64 73 68 61 62 6a 6a 71 20 3d 20 52 61 6e 67 65 28 22 41 33 22 29 2e 56 61 6c 75 65 } //01 00  tadlbntqflqtbtpeeoidjzjdnnxdshabjjq = Range("A3").Value
		$a_00_2 = {71 6a 62 74 6e 6e 70 66 64 20 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 61 6e 67 65 28 22 41 34 22 29 2e 56 61 6c 75 65 29 } //01 00  qjbtnnpfd  = CreateObject(Range("A4").Value)
		$a_00_3 = {71 6a 62 74 6e 6e 70 66 64 2e 43 72 65 61 74 65 28 74 61 64 6c 62 6e 74 71 66 6c 71 74 62 74 70 65 65 6f 69 64 6a 7a 6a 64 6e 6e 78 64 73 68 61 62 6a 6a 71 29 } //01 00  qjbtnnpfd.Create(tadlbntqflqtbtpeeoidjzjdnnxdshabjjq)
		$a_00_4 = {52 61 6e 67 65 28 22 4d 35 22 29 2e 53 65 6c 65 63 74 } //00 00  Range("M5").Select
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Obfuse_RSM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 61 6e 67 65 28 22 41 31 3a 4a 31 38 22 29 2e 53 65 6c 65 63 74 } //01 00  Range("A1:J18").Select
		$a_00_1 = {6f 70 73 6c 6d 67 74 72 64 73 76 75 6b 6f 64 62 6e 6a 6f 78 63 74 69 67 7a 6e 6b 66 72 62 65 64 77 6c 72 74 66 6b 7a 78 63 69 69 73 75 66 6f 73 6c 6d 72 6b 62 6f 77 75 68 6c 6d 79 76 6e 7a 63 6e 72 79 7a 77 6a 77 20 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 61 6e 67 65 28 22 41 31 32 33 22 29 2e 56 61 6c 75 65 29 } //01 00  opslmgtrdsvukodbnjoxctigznkfrbedwlrtfkzxciisufoslmrkbowuhlmyvnzcnryzwjw  = CreateObject(Range("A123").Value)
		$a_00_2 = {6d 79 76 6e 7a 63 6e 72 79 7a 77 6a 77 2e 43 72 65 61 74 65 28 73 6f 67 6c 62 6a 78 77 62 65 63 74 62 63 6e 6f 6f 68 65 61 74 } //01 00  myvnzcnryzwjw.Create(soglbjxwbectbcnooheat
		$a_00_3 = {52 61 6e 67 65 28 22 4d 35 22 29 2e 53 65 6c 65 63 74 } //01 00  Range("M5").Select
		$a_00_4 = {6a 71 6b 7a 78 6f 78 6b 71 6f 63 75 75 6d 7a 6a 75 73 73 63 66 74 78 7a 6d 72 76 66 67 79 74 69 6b 66 6a 78 77 6c 65 76 7a 6d 6b 71 7a 7a 68 70 6f 66 75 70 6c 79 20 3d 20 52 61 6e 67 65 28 22 41 31 37 22 29 2e 56 61 6c 75 65 } //00 00  jqkzxoxkqocuumzjusscftxzmrvfgytikfjxwlevzmkqzzhpofuply = Range("A17").Value
	condition:
		any of ($a_*)
 
}