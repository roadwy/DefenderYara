
rule Ransom_MSIL_Cryptolocker_DP_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 08 00 00 32 00 "
		
	strings :
		$a_81_0 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //32 00  your files have been encrypted
		$a_81_1 = {53 74 6f 6e 6b 73 56 69 72 75 73 } //14 00  StonksVirus
		$a_81_2 = {2e 68 6a 67 6b 64 66 } //14 00  .hjgkdf
		$a_81_3 = {2e 4e 6f 74 53 74 6f 6e 6b 73 } //03 00  .NotStonks
		$a_81_4 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //03 00  DisableRealtimeMonitoring
		$a_81_5 = {44 65 6c 65 74 65 64 46 69 6c 65 73 41 6d 6d 6f 75 6e 74 2e 74 78 74 } //01 00  DeletedFilesAmmount.txt
		$a_81_6 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //01 00  DisableAntiSpyware
		$a_81_7 = {42 69 74 63 6f 69 6e 20 77 61 6c 6c 65 74 3a } //00 00  Bitcoin wallet:
	condition:
		any of ($a_*)
 
}