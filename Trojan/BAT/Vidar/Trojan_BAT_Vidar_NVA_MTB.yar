
rule Trojan_BAT_Vidar_NVA_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 76 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c 08 0d } //5
		$a_01_1 = {43 00 6f 00 37 00 66 00 65 00 72 00 65 00 37 00 63 00 65 00 } //1 Co7fere7ce
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Vidar_NVA_MTB_2{
	meta:
		description = "Trojan:BAT/Vidar.NVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 03 11 07 16 73 ?? 00 00 0a 13 0b 20 ?? 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? 00 00 00 26 20 ?? 00 00 00 38 ?? 00 00 00 fe 0c 09 00 } //5
		$a_01_1 = {66 69 6e 61 6c 2e 42 72 69 64 67 65 73 2e 49 6e 64 65 78 65 72 52 65 70 6f 73 69 74 6f 72 79 42 72 69 64 67 65 2e 72 65 73 6f 75 72 63 65 73 } //1 final.Bridges.IndexerRepositoryBridge.resources
		$a_01_2 = {51 69 72 68 6b 72 79 67 62 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Qirhkrygb.Properties
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_BAT_Vidar_NVA_MTB_3{
	meta:
		description = "Trojan:BAT/Vidar.NVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 07 00 00 2b 1f 20 28 ?? 00 00 2b 28 ?? 00 00 2b 02 1f 30 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 73 ?? 00 00 0a 28 ?? 00 00 06 03 6f ?? 00 00 0a 28 ?? 00 00 06 0c 08 73 ?? 00 00 0a 07 06 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 28 ?? 00 00 2b 16 fe 01 } //5
		$a_01_1 = {62 6f 75 6c 69 6e 67 34 66 65 65 74 5f 6d 65 6d 62 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 bouling4feet_member.My.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}