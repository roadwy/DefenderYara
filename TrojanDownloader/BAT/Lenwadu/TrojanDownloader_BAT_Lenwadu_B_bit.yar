
rule TrojanDownloader_BAT_Lenwadu_B_bit{
	meta:
		description = "TrojanDownloader:BAT/Lenwadu.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 75 00 2e 00 6c 00 65 00 77 00 64 00 2e 00 73 00 65 00 2f 00 } //2 https://u.lewd.se/
		$a_01_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00 } //1 DownloadData
		$a_01_2 = {53 61 6e 64 62 6f 78 69 65 52 70 63 53 73 } //1 SandboxieRpcSs
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}