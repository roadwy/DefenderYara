
rule TrojanDownloader_Win64_NRLoader_A_MTB{
	meta:
		description = "TrojanDownloader:Win64/NRLoader.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 33 c4 48 89 45 f8 45 33 ?? 48 8d 15 ?? 21 00 00 33 c9 ff 15 ?? 1f 00 00 48 8d 0d ?? 21 00 00 ff 15 ?? 1f 00 00 4c 8b f8 } //2
		$a_01_1 = {4e 69 67 68 74 52 75 73 74 43 6c 69 65 6e 74 } //2 NightRustClient
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}