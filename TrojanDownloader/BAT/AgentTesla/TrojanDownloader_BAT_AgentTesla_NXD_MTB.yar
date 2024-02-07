
rule TrojanDownloader_BAT_AgentTesla_NXD_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 95 02 20 09 02 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 2b 00 00 00 04 00 00 00 01 00 00 00 04 00 00 00 01 00 00 00 25 00 00 00 0e 00 00 00 01 00 00 00 03 00 00 00 01 00 00 00 01 00 00 00 02 00 00 00 01 } //01 00 
		$a_01_1 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //01 00  DynamicInvoke
		$a_01_2 = {47 65 74 44 6f 6d 61 69 6e } //01 00  GetDomain
		$a_01_3 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //01 00  CreateDelegate
		$a_01_4 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //01 00  TripleDESCryptoServiceProvider
		$a_01_5 = {43 6f 6d 70 75 74 65 48 61 73 68 } //01 00  ComputeHash
		$a_01_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_7 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00  DownloadData
	condition:
		any of ($a_*)
 
}