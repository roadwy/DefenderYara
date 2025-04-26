
rule TrojanDownloader_O97M_Donoff_SMB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SMB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 20 43 68 72 28 33 34 29 20 26 20 22 68 74 74 70 3a 2f 2f 73 63 61 6c 61 64 65 76 65 6c 6f 70 6d 65 6e 74 73 2e 73 63 61 6c 61 64 65 76 63 6f 2e 63 6f 6d 2f 31 37 2f 43 6f 6e 73 6f 6c 65 41 70 70 31 38 2e 65 78 22 20 26 } //2 & Chr(34) & "http://scaladevelopments.scaladevco.com/17/ConsoleApp18.ex" &
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule TrojanDownloader_O97M_Donoff_SMB_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.SMB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 70 41 59 78 62 76 51 2e 77 59 38 48 6b 52 74 54 6c 51 78 37 5f 6d 44 5f 5f 38 75 6f } //1 hpAYxbvQ.wY8HkRtTlQx7_mD__8uo
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 55 5f 75 6e 69 75 52 79 59 49 70 6f 62 53 69 29 } //1 = CreateObject(U_uniuRyYIpobSi)
		$a_01_2 = {2e 52 75 6e 28 } //1 .Run(
		$a_01_3 = {3d 20 43 68 72 28 47 5f 5f 5f 55 20 2d 20 36 30 29 } //1 = Chr(G___U - 60)
		$a_01_4 = {57 77 42 54 41 46 6b 41 55 77 42 55 41 45 55 41 54 51 41 75 41 48 51 41 5a 51 42 59 41 46 51 41 4c 67 42 46 41 47 34 41 51 77 42 76 41 47 51 41 53 51 42 75 41 47 63 41 58 51 41 36 41 44 6f 41 64 51 42 4f 41 45 6b 41 59 77 42 50 41 45 51 41 52 51 41 75 41 45 63 41 5a 51 42 30 41 46 4d 41 64 41 42 79 41 47 6b 41 62 67 42 48 41 43 67 41 57 77 42 7a 41 48 6b 41 55 77 42 55 41 47 } //1 WwBTAFkAUwBUAEUATQAuAHQAZQBYAFQALgBFAG4AQwBvAGQASQBuAGcAXQA6ADoAdQBOAEkAYwBPAEQARQAuAEcAZQB0AFMAdAByAGkAbgBHACgAWwBzAHkAUwBUAG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}