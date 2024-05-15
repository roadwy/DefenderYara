
rule Trojan_MacOS_RealstStealer_B_MTB{
	meta:
		description = "Trojan:MacOS/RealstStealer.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 62 61 74 74 6c 65 6e 65 74 43 68 65 63 6b 65 72 } //01 00  main.battlenetChecker
		$a_01_1 = {72 75 6e 74 69 6d 65 2e 73 74 65 61 6c 57 6f 72 6b } //01 00  runtime.stealWork
		$a_01_2 = {6d 61 69 6e 2e 67 65 74 53 61 66 65 53 74 6f 72 61 67 65 53 65 63 72 65 74 4b 65 79 73 } //01 00  main.getSafeStorageSecretKeys
		$a_01_3 = {6d 61 69 6e 2e 62 69 6e 61 6e 63 65 43 68 65 63 6b 65 72 } //01 00  main.binanceChecker
		$a_01_4 = {43 43 6f 70 79 46 46 6f 6c 64 65 72 43 6f 6e 74 65 6e 74 73 } //00 00  CCopyFFolderContents
	condition:
		any of ($a_*)
 
}