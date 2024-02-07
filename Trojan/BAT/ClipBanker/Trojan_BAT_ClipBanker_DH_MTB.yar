
rule Trojan_BAT_ClipBanker_DH_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1d 00 1d 00 0b 00 00 14 00 "
		
	strings :
		$a_81_0 = {57 69 6e 4f 53 44 73 6b } //14 00  WinOSDsk
		$a_81_1 = {57 69 6e 48 6f 73 74 } //01 00  WinHost
		$a_81_2 = {48 6f 74 69 6e 67 } //01 00  Hoting
		$a_81_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_4 = {43 6c 69 70 62 6f 61 72 64 } //01 00  Clipboard
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_6 = {47 65 74 44 61 74 61 50 72 65 73 65 6e 74 } //01 00  GetDataPresent
		$a_81_7 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_8 = {4d 75 74 65 78 } //01 00  Mutex
		$a_81_9 = {52 65 67 65 78 } //01 00  Regex
		$a_81_10 = {46 69 6c 65 44 72 6f 70 } //00 00  FileDrop
	condition:
		any of ($a_*)
 
}