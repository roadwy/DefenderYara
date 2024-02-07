
rule Trojan_BAT_Nanocore_MFP_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0e 00 00 14 00 "
		
	strings :
		$a_00_0 = {24 63 31 36 61 35 32 38 61 2d 34 63 65 38 2d 34 61 35 38 2d 39 34 65 31 2d 66 37 35 64 36 39 66 39 34 63 62 39 } //14 00  $c16a528a-4ce8-4a58-94e1-f75d69f94cb9
		$a_00_1 = {24 63 65 64 38 39 66 62 35 2d 65 34 62 32 2d 34 32 30 37 2d 38 62 34 30 2d 33 32 34 62 36 64 33 62 32 37 30 39 } //01 00  $ced89fb5-e4b2-4207-8b40-324b6d3b2709
		$a_81_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_81_3 = {53 75 73 70 65 6e 64 4c 61 79 6f 75 74 } //01 00  SuspendLayout
		$a_81_4 = {67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //01 00  get_ResourceManager
		$a_81_5 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //01 00  get_Assembly
		$a_81_6 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d 78 } //01 00  MemoryStreamx
		$a_81_7 = {44 65 66 6c 61 74 65 53 74 72 65 61 6d } //01 00  DeflateStream
		$a_81_8 = {67 65 74 5f 57 65 62 53 65 72 76 69 63 65 73 } //01 00  get_WebServices
		$a_81_9 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_81_10 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_81_11 = {47 65 74 48 61 73 68 43 6f 64 65 } //01 00  GetHashCode
		$a_81_12 = {53 70 65 63 69 61 6c 46 6f 6c 64 65 72 } //01 00  SpecialFolder
		$a_81_13 = {42 6c 6f 63 6b 43 6f 70 79 } //00 00  BlockCopy
	condition:
		any of ($a_*)
 
}