
rule Trojan_AndroidOS_Rewardsteal_N{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.N,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {48 61 72 6d 66 75 6c 41 70 70 52 65 63 65 69 76 65 72 } //02 00  HarmfulAppReceiver
		$a_01_1 = {70 61 6b 61 2f 70 6f 2f 54 68 61 6e 6b } //00 00  paka/po/Thank
	condition:
		any of ($a_*)
 
}
rule Trojan_AndroidOS_Rewardsteal_N_2{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.N,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {65 78 70 69 72 79 20 73 68 6f 75 6c 64 20 62 65 20 61 74 6c 65 61 73 74 20 32 30 32 33 33 } //01 00  expiry should be atleast 20233
		$a_01_1 = {44 65 62 69 74 20 63 61 72 64 20 6e 6f 74 20 63 6f 72 72 65 63 74 65 64 } //01 00  Debit card not corrected
		$a_01_2 = {46 6f 75 72 74 68 50 61 67 65 6d 28 64 65 62 69 74 3d } //00 00  FourthPagem(debit=
	condition:
		any of ($a_*)
 
}