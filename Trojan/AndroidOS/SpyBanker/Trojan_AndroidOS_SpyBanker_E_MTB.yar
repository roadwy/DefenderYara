
rule Trojan_AndroidOS_SpyBanker_E_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 69 74 73 6f 6c 75 74 69 6f 6e 2e 69 6e 66 6f 2f 3f 6f 64 6a 61 73 69 6a 64 61 6f 73 69 } //01 00  bitsolution.info/?odjasijdaosi
		$a_00_1 = {62 72 61 7a 69 6c 69 61 6e 6b 69 6e 67 73 2e 64 64 6e 73 2e 6e 65 74 2f 72 65 6e 65 77 } //01 00  braziliankings.ddns.net/renew
		$a_00_2 = {73 65 72 76 69 63 65 2e 77 65 62 76 69 65 77 2e 77 65 62 6b 69 73 7a } //01 00  service.webview.webkisz
		$a_00_3 = {6c 6f 61 64 2e 70 68 70 3f 68 77 69 64 3d } //01 00  load.php?hwid=
		$a_00_4 = {2f 6d 6f 62 69 6c 65 63 6f 6e 66 69 67 2e 70 68 70 } //01 00  /mobileconfig.php
		$a_00_5 = {78 71 64 74 42 75 70 75 69 69 71 77 75 } //00 00  xqdtBupuiiqwu
	condition:
		any of ($a_*)
 
}