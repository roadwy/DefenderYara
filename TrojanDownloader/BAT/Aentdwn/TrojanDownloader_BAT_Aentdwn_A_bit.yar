
rule TrojanDownloader_BAT_Aentdwn_A_bit{
	meta:
		description = "TrojanDownloader:BAT/Aentdwn.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6d 00 72 00 61 00 6e 00 74 00 69 00 66 00 75 00 6e 00 2e 00 74 00 6b 00 2f 00 [0-2f] 77 00 69 00 6e 00 69 00 63 00 63 00 2e 00 66 00 69 00 6c 00 65 00 } //1
		$a_01_1 = {77 00 69 00 6e 00 69 00 63 00 63 00 2e 00 65 00 78 00 65 00 } //1 winicc.exe
		$a_01_2 = {50 00 75 00 62 00 67 00 48 00 61 00 63 00 6b 00 54 00 6f 00 6f 00 6c 00 } //1 PubgHackTool
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}