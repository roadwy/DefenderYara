
rule MonitoringTool_Win64_AwardKeylogger{
	meta:
		description = "MonitoringTool:Win64/AwardKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 5c 6b 6c 2e 65 78 65 00 } //01 00 
		$a_00_1 = {2f 53 69 6c 65 6e 74 20 2f 4e 6f 49 63 6f 6e } //01 00  /Silent /NoIcon
		$a_03_2 = {80 7b 10 aa 74 08 c6 04 25 00 00 00 00 78 44 8b 44 24 90 01 01 48 8b 54 24 90 01 01 48 8b cb e8 90 01 04 b2 20 48 8b cb e8 90 01 04 80 7b 10 aa 74 08 c6 04 25 00 00 00 00 78 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}