
rule Trojan_BAT_Tnega_DFS_MTB{
	meta:
		description = "Trojan:BAT/Tnega.DFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 00 6f 00 6c 00 64 00 2e 00 65 00 78 00 65 00 } //1 Gold.exe
		$a_01_1 = {47 00 6f 00 6c 00 64 00 4d 00 55 00 23 00 40 00 31 00 32 00 33 00 4d 00 55 00 } //1 GoldMU#@123MU
		$a_01_2 = {31 00 30 00 33 00 2e 00 31 00 34 00 35 00 2e 00 34 00 2e 00 32 00 30 00 38 00 } //1 103.145.4.208
		$a_81_3 = {55 4a 69 7d 51 45 66 7a 4e 46 66 7a 4e 44 63 77 50 64 } //1 UJi}QEfzNFfzNDcwPd
		$a_81_4 = {50 61 63 6b 65 74 46 69 6c 65 4d 61 6e 61 67 65 72 5f 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 PacketFileManager_DownloadFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}