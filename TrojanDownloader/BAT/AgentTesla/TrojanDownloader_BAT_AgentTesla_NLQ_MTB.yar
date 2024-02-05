
rule TrojanDownloader_BAT_AgentTesla_NLQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NLQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 42 00 64 00 4f 00 36 00 4e 00 77 00 49 00 50 00 70 00 6d 00 4d 00 5a 00 4e 00 44 00 4a 00 41 00 73 00 44 00 67 00 63 00 51 00 3d } //01 00 
		$a_01_1 = {74 00 76 00 39 00 55 00 41 00 66 00 2f 00 57 00 6a 00 59 00 42 00 4f 00 46 00 2b 00 52 00 65 00 67 00 70 00 65 00 76 00 63 00 49 00 6a 00 64 00 64 00 6c 00 4f 00 4d 00 67 00 57 00 77 00 34 00 32 00 58 00 6c 00 46 00 31 00 4d 00 51 00 51 00 6d 00 4e } //01 00 
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_80_3 = {76 70 78 33 78 2e 50 72 6f 70 65 72 74 69 65 73 2e 59 74 54 68 31 } //vpx3x.Properties.YtTh1  01 00 
		$a_80_4 = {53 74 79 6c 75 73 4c 6f 67 69 63 } //StylusLogic  01 00 
		$a_80_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //InvokeMember  01 00 
		$a_80_6 = {76 70 78 33 78 3b 63 6f 6d 70 6f 6e 65 6e 74 2f 6d 61 69 6e 77 69 6e 64 6f 77 2e 78 61 6d 6c } //vpx3x;component/mainwindow.xaml  00 00 
	condition:
		any of ($a_*)
 
}