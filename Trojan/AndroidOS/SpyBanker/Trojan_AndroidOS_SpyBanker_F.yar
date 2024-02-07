
rule Trojan_AndroidOS_SpyBanker_F{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.F,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {76 6e 63 5f 61 6c 6c 6f 77 31 30 } //02 00  vnc_allow10
		$a_01_1 = {70 72 6f 74 65 63 74 32 30 32 30 5f 73 74 72 } //02 00  protect2020_str
		$a_01_2 = {73 63 68 65 74 5f 73 77 73 } //02 00  schet_sws
		$a_01_3 = {73 75 6e 73 65 74 5f 63 6d 64 } //00 00  sunset_cmd
	condition:
		any of ($a_*)
 
}