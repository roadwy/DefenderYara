
rule TrojanSpy_Win32_Gauss_plugin_H{
	meta:
		description = "TrojanSpy:Win32/Gauss.plugin!H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 7d 24 25 74 90 01 01 83 7d 24 03 0f 85 90 01 04 89 75 d0 c6 45 ef 00 83 7d 24 25 8d 5e 68 74 90 01 01 8d 5e 5e 89 7d dc 8b 45 dc 83 f8 04 90 00 } //01 00 
		$a_02_1 = {81 7d f0 2b 7f 39 eb 75 90 01 01 56 8d 45 f4 50 6a 04 8d 45 fc 50 ff 75 f8 ff d3 90 00 } //01 00 
		$a_00_2 = {74 00 61 00 72 00 67 00 65 00 74 00 2e 00 6c 00 6e 00 6b 00 } //00 00  target.lnk
	condition:
		any of ($a_*)
 
}