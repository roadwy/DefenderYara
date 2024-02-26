
rule Trojan_AndroidOS_Gudex_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Gudex.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 70 69 2e 6c 65 67 65 6e 64 73 77 6f 72 6c 64 2e 69 6e 2f 4f 6e 6c 69 6e 65 2f 43 72 61 63 6b 53 6e 69 70 65 72 2f 61 73 75 2e 7a 69 70 } //01 00  api.legendsworld.in/Online/CrackSniper/asu.zip
		$a_01_1 = {63 6f 6d 2e 43 72 61 63 6b 53 6e 69 70 65 72 2e 75 69 2e 4f 76 65 72 6c 61 79 } //01 00  com.CrackSniper.ui.Overlay
		$a_01_2 = {4c 6f 62 62 79 42 79 70 61 73 73 50 } //01 00  LobbyBypassP
		$a_01_3 = {72 6f 6e 61 6b 54 52 55 45 } //01 00  ronakTRUE
		$a_01_4 = {52 65 63 6f 72 64 65 72 46 61 6b 65 } //00 00  RecorderFake
	condition:
		any of ($a_*)
 
}