
rule Trojan_AndroidOS_AgentSmith_A_MTB{
	meta:
		description = "Trojan:AndroidOS/AgentSmith.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0b 00 0b 00 07 00 00 03 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 69 6e 66 65 63 74 69 6f 6e 61 70 6b 2e 70 61 74 63 68 4d 61 69 6e } //03 00  com.infectionapk.patchMain
		$a_00_1 = {72 65 73 61 2e 64 61 74 61 2e 65 6e 63 72 79 } //03 00  resa.data.encry
		$a_00_2 = {61 64 73 64 6b 2e 7a 69 70 } //01 00  adsdk.zip
		$a_00_3 = {4c 63 6f 6d 2f 6a 69 6f 2f 6a 69 6f 70 6c 61 79 2f 74 76 2f 61 70 70 6c 69 63 61 74 69 6f 6e 2f 4a 69 6f 54 56 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00  Lcom/jio/jioplay/tv/application/JioTVApplication
		$a_00_4 = {4c 63 6f 6d 2f 6c 65 6e 6f 76 6f 2f 61 6e 79 73 68 61 72 65 2f 41 6e 79 53 68 61 72 65 41 70 70 3b } //01 00  Lcom/lenovo/anyshare/AnyShareApp;
		$a_00_5 = {4c 63 6f 6d 2f 66 6c 69 70 6b 61 72 74 2f 61 6e 64 72 6f 69 64 2f 69 6e 69 74 2f 46 6c 69 70 6b 61 72 74 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00  Lcom/flipkart/android/init/FlipkartApplication
		$a_00_6 = {4c 63 6f 6d 2f 77 68 61 74 73 61 70 70 2f 41 70 70 53 68 65 6c 6c 3b } //00 00  Lcom/whatsapp/AppShell;
		$a_00_7 = {5d 04 00 00 d3 f8 } //03 80 
	condition:
		any of ($a_*)
 
}