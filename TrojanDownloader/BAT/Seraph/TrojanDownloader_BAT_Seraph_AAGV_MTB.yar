
rule TrojanDownloader_BAT_Seraph_AAGV_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.AAGV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 02 16 28 ?? 00 00 06 13 03 20 01 00 00 00 7e ?? 03 00 04 7b ?? 02 00 04 39 ?? ff ff ff 26 20 00 00 00 00 38 ?? ff ff ff 11 0b 11 02 16 1a 6f ?? 00 00 0a 26 20 00 00 00 00 7e ?? 03 00 04 7b ?? 03 00 04 3a ?? ff ff ff 26 20 00 00 00 00 38 ?? ff ff ff 11 0b 16 73 ?? 00 00 0a 13 09 20 03 00 00 00 7e ?? 03 00 04 7b ?? 03 00 04 39 ?? ff ff ff 26 20 01 00 00 00 38 } //2
		$a_01_1 = {44 6e 73 43 6c 69 65 6e 74 2e 53 68 61 72 65 64 2e 47 6c 6f 62 61 6c 4d 61 70 2e 72 65 73 6f 75 72 63 65 73 } //1 DnsClient.Shared.GlobalMap.resources
		$a_01_2 = {62 00 6f 00 74 00 6e 00 65 00 74 00 6c 00 6f 00 67 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 50 00 75 00 72 00 65 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 50 00 77 00 61 00 65 00 6e 00 6f 00 2e 00 76 00 64 00 66 00 } //1 botnetlogs.com/PureCrypter/panel/uploads/Pwaeno.vdf
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}