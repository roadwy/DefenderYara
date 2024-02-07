
rule Trojan_BAT_Remcos_MQ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 95 02 20 09 02 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 28 00 00 00 07 00 00 00 01 00 00 00 0a } //01 00 
		$a_01_1 = {24 38 39 39 63 32 34 63 34 2d 32 62 36 30 2d 34 61 61 35 2d 38 33 30 39 2d 37 32 62 64 33 64 33 64 31 30 64 33 } //01 00  $899c24c4-2b60-4aa5-8309-72bd3d3d10d3
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_3 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_4 = {57 65 62 43 6c 69 65 6e 74 } //01 00  WebClient
		$a_01_5 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}