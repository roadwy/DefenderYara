
rule Trojan_BAT_Nanocore_ABH_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {a2 09 17 7e 90 01 03 0a a2 09 18 06 72 90 01 03 70 6f 90 01 03 0a a2 09 13 04 08 90 00 } //2
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_2 = {43 00 41 00 63 00 63 00 50 00 72 00 6f 00 70 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 43 00 6c 00 61 00 73 00 73 00 2e 00 49 00 41 00 63 00 63 00 50 00 72 00 6f 00 70 00 53 00 65 00 72 00 76 00 65 00 72 00 } //1 CAccPropServicesClass.IAccPropServer
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_Nanocore_ABH_MTB_2{
	meta:
		description = "Trojan:BAT/Nanocore.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_03_0 = {26 2a d0 2b 90 01 02 06 26 2a 90 0a 30 00 28 0f 90 01 02 06 6f 3f 90 01 02 0a 07 75 24 90 01 02 01 08 75 03 90 01 02 1b 16 6f 40 90 01 02 0a 07 75 24 90 01 02 01 28 41 90 01 01 00 0a 90 00 } //5
		$a_01_1 = {53 68 75 74 64 6f 77 6e 4d 6f 64 65 } //1 ShutdownMode
		$a_01_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_4 = {44 65 66 6c 61 74 65 53 74 72 65 61 6d } //1 DeflateStream
		$a_01_5 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //1 CompressionMode
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}