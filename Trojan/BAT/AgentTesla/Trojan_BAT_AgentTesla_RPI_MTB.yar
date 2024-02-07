
rule Trojan_BAT_AgentTesla_RPI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 72 00 64 00 73 00 47 00 65 00 74 00 42 00 79 00 53 00 72 00 64 00 73 00 74 00 65 00 41 00 72 00 72 00 53 00 72 00 64 00 73 00 61 00 79 00 41 00 73 00 79 00 53 00 72 00 64 00 73 00 6e 00 63 00 } //01 00  SrdsGetBySrdsteArrSrdsayAsySrdsnc
		$a_01_1 = {31 00 38 00 35 00 2e 00 32 00 32 00 32 00 2e 00 35 00 38 00 2e 00 35 00 36 00 } //01 00  185.222.58.56
		$a_01_2 = {74 00 72 00 79 00 2e 00 70 00 6e 00 67 00 } //01 00  try.png
		$a_01_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00  powershell
		$a_01_4 = {51 00 64 00 64 00 79 00 77 00 62 00 78 00 61 00 76 00 67 00 74 00 62 00 6a 00 61 00 75 00 6b 00 63 00 6c 00 64 00 72 00 70 00 6d 00 63 00 6d 00 } //01 00  Qddywbxavgtbjaukcldrpmcm
		$a_01_5 = {48 74 74 70 43 6c 69 65 6e 74 } //00 00  HttpClient
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00  cdn.discordapp.com
		$a_01_1 = {41 00 6c 00 75 00 70 00 6f 00 6c 00 2e 00 70 00 6e 00 67 00 } //01 00  Alupol.png
		$a_01_2 = {47 00 65 00 74 00 42 00 79 00 74 00 65 00 41 00 72 00 72 00 61 00 79 00 41 00 73 00 79 00 6e 00 63 00 } //01 00  GetByteArrayAsync
		$a_01_3 = {53 00 6c 00 65 00 65 00 70 00 } //01 00  Sleep
		$a_01_4 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 54 00 68 00 72 00 65 00 61 00 64 00 69 00 6e 00 67 00 2e 00 54 00 68 00 72 00 65 00 61 00 64 00 } //01 00  System.Threading.Thread
		$a_01_5 = {46 00 6f 00 6f 00 74 00 65 00 63 00 61 00 64 00 69 00 62 00 77 00 68 00 74 00 73 00 70 00 68 00 6e 00 61 00 61 00 76 00 79 00 6f 00 6e 00 } //00 00  Footecadibwhtsphnaavyon
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RPI_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 12 00 00 0a 00 "
		
	strings :
		$a_01_0 = {00 00 00 00 02 00 00 01 57 94 02 28 09 02 00 00 00 fa 25 33 00 16 00 00 } //01 00 
		$a_01_1 = {46 69 6c 65 53 74 72 65 61 6d } //01 00  FileStream
		$a_01_2 = {67 65 74 5f 4c 65 6e 67 74 68 } //01 00  get_Length
		$a_01_3 = {47 65 74 46 69 6c 65 73 } //01 00  GetFiles
		$a_01_4 = {47 65 74 44 69 72 65 63 74 6f 72 69 65 73 } //01 00  GetDirectories
		$a_01_5 = {4d 61 72 73 68 61 6c } //01 00  Marshal
		$a_01_6 = {53 79 73 74 65 6d 2e 54 65 78 74 } //01 00  System.Text
		$a_01_7 = {45 6e 63 6f 64 69 6e 67 } //01 00  Encoding
		$a_01_8 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_01_9 = {45 6e 76 69 72 6f 6e 6d 65 6e 74 } //01 00  Environment
		$a_01_10 = {53 70 65 63 69 61 6c 46 6f 6c 64 65 72 } //01 00  SpecialFolder
		$a_01_11 = {49 6e 69 74 69 61 6c 69 7a 65 41 72 72 61 79 } //01 00  InitializeArray
		$a_01_12 = {53 70 6c 69 74 } //01 00  Split
		$a_01_13 = {43 6f 6e 63 61 74 } //01 00  Concat
		$a_01_14 = {67 65 74 5f 41 53 43 49 49 } //01 00  get_ASCII
		$a_01_15 = {67 65 74 5f 55 6e 69 63 6f 64 65 } //01 00  get_Unicode
		$a_01_16 = {52 65 6d 6f 76 65 } //01 00  Remove
		$a_01_17 = {56 61 6c 75 65 54 79 70 65 } //00 00  ValueType
	condition:
		any of ($a_*)
 
}