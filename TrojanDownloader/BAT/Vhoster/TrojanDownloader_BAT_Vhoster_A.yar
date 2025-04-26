
rule TrojanDownloader_BAT_Vhoster_A{
	meta:
		description = "TrojanDownloader:BAT/Vhoster.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {0d 09 16 08 16 1f 10 28 20 00 00 0a 09 16 08 1f 0f 1f 10 28 20 00 00 0a 06 08 6f 21 00 00 0a } //1
		$a_03_1 = {13 05 12 05 fe 16 ?? ?? ?? ?? 6f ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0c 73 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 08 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 0d 09 6f } //1
		$a_00_2 = {77 00 69 00 6e 00 68 00 6f 00 73 00 74 00 65 00 72 00 } //1 winhoster
		$a_00_3 = {4e 00 70 00 66 00 20 00 4d 00 5a 00 4b 00 41 00 6a 00 6d 00 } //1 Npf MZKAjm
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}