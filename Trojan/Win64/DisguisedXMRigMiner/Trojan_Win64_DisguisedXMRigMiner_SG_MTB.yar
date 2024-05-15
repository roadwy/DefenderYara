
rule Trojan_Win64_DisguisedXMRigMiner_SG_MTB{
	meta:
		description = "Trojan:Win64/DisguisedXMRigMiner.SG!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 6f 6c 5f 77 61 6c 6c 65 74 } //01 00  pool_wallet
		$a_01_1 = {6e 69 63 65 68 61 73 68 } //01 00  nicehash
		$a_01_2 = {64 61 65 6d 6f 6e 2d 70 6f 6c 6c 2d 69 6e 74 65 72 76 61 6c } //01 00  daemon-poll-interval
		$a_01_3 = {6d 69 6e 69 6e 67 2e 61 75 74 68 6f 72 69 7a 65 20 63 61 6c 6c 20 66 61 69 6c 65 64 } //01 00  mining.authorize call failed
		$a_01_4 = {6d 69 6e 69 6e 67 2e 65 78 74 72 61 6e 6f 6e 63 65 2e 73 75 62 73 63 72 69 62 65 } //01 00  mining.extranonce.subscribe
		$a_01_5 = {76 00 61 00 20 00 76 00 79 00 68 00 72 00 61 00 7a 00 65 00 6e 00 61 00 2e 00 } //01 00  va vyhrazena.
		$a_01_6 = {64 00 78 00 73 00 65 00 74 00 75 00 70 00 2e 00 65 00 78 00 65 00 } //00 00  dxsetup.exe
	condition:
		any of ($a_*)
 
}