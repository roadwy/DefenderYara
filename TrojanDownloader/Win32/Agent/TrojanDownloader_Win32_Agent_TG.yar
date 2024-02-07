
rule TrojanDownloader_Win32_Agent_TG{
	meta:
		description = "TrojanDownloader:Win32/Agent.TG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 3a 5c 33 36 30 5c 33 36 30 53 61 66 65 2e 72 65 67 } //01 00  d:\360\360Safe.reg
		$a_03_1 = {68 c8 00 00 00 e8 90 01 02 ff ff e8 90 01 02 ff ff 68 c8 00 00 00 e8 90 01 02 ff ff e8 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}