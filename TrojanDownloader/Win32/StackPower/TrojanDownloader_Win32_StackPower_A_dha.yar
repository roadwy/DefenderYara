
rule TrojanDownloader_Win32_StackPower_A_dha{
	meta:
		description = "TrojanDownloader:Win32/StackPower.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 00 6e 00 74 00 65 00 6c 00 5c 00 55 00 4e 00 50 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 55 00 70 00 64 00 61 00 74 00 65 00 73 00 5c 00 6f 00 70 00 65 00 6e 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 Intel\UNP\ProgramUpdates\openexplorer.exe
		$a_01_1 = {2d 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 20 00 27 00 55 00 73 00 65 00 72 00 4f 00 4f 00 45 00 42 00 72 00 6f 00 6b 00 65 00 72 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 27 00 } //1 -Description 'UserOOEBroker Update'
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}