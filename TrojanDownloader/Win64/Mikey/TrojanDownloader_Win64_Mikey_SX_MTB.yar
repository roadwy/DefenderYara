
rule TrojanDownloader_Win64_Mikey_SX_MTB{
	meta:
		description = "TrojanDownloader:Win64/Mikey.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b d0 48 8b cb ff 15 ?? ?? ?? ?? 48 89 74 24 ?? 4c 8b cf 89 74 24 ?? 45 33 c0 33 d2 48 89 74 24 ?? 48 8b cb ff 15 } //20
		$a_01_1 = {47 6c 6f 62 61 6c 5c 53 79 73 74 65 6d 48 65 61 6c 74 68 4d 6f 6e 69 74 6f 72 } //10 Global\SystemHealthMonitor
		$a_01_2 = {67 61 74 65 2e 70 68 70 } //5 gate.php
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}