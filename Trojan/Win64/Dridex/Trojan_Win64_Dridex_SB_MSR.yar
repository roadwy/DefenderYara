
rule Trojan_Win64_Dridex_SB_MSR{
	meta:
		description = "Trojan:Win64/Dridex.SB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 00 65 00 66 00 65 00 72 00 73 00 43 00 68 00 72 00 6f 00 6d 00 69 00 75 00 6d 00 46 00 6c 00 61 00 73 00 68 00 } //01 00  refersChromiumFlash
		$a_01_1 = {42 00 65 00 61 00 63 00 68 00 61 00 74 00 6f 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 } //05 00  BeachatoGoogle
		$a_01_2 = {54 00 2b 00 69 00 67 00 48 00 70 00 2a 00 32 00 63 00 79 00 75 00 71 00 24 00 42 00 4d 00 } //05 00  T+igHp*2cyuq$BM
		$a_01_3 = {4b 00 59 00 64 00 6a 00 3f 00 54 00 2b 00 69 00 67 00 48 00 70 00 2a 00 32 00 63 00 79 00 75 00 71 00 24 00 42 00 4d 00 } //01 00  KYdj?T+igHp*2cyuq$BM
		$a_01_4 = {47 65 74 55 73 65 72 44 65 66 61 75 6c 74 4c 6f 63 61 6c 65 4e 61 6d 65 } //01 00  GetUserDefaultLocaleName
		$a_01_5 = {4a 75 70 6f 66 62 6c 6f 63 6b 65 64 } //01 00  Jupofblocked
		$a_01_6 = {4d 6f 64 69 66 79 45 78 65 63 75 74 65 50 72 6f 74 65 63 74 69 6f 6e 53 75 70 70 6f 72 74 } //01 00  ModifyExecuteProtectionSupport
		$a_01_7 = {54 72 61 63 6b 50 6f 70 75 70 4d 65 6e 75 } //00 00  TrackPopupMenu
	condition:
		any of ($a_*)
 
}