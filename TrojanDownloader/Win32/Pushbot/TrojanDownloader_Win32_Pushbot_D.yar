
rule TrojanDownloader_Win32_Pushbot_D{
	meta:
		description = "TrojanDownloader:Win32/Pushbot.D,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {43 00 3a 00 5c 00 41 00 6c 00 6c 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 90 02 20 2e 00 76 00 62 00 70 00 90 00 } //01 00 
		$a_00_1 = {74 68 70 74 2f 3a 77 2f 77 77 6d 2e 73 79 61 70 65 63 63 2e 6d 6f 62 2f 6f 72 73 77 2f 65 72 62 77 6f 65 73 61 2e 70 73 } //01 00  thpt/:w/wwm.syapecc.mob/orsw/erbwoesa.ps
		$a_00_2 = {74 68 70 74 2f 3a 39 2f 2e 33 37 31 2e 34 34 39 38 2e 2f 37 64 7e 6e 65 72 69 6c 75 2f } //00 00  thpt/:9/.371.4498./7d~nerilu/
	condition:
		any of ($a_*)
 
}