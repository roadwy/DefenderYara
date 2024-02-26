
rule Ransom_MSIL_Cryptolocker_DX_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 09 00 00 32 00 "
		
	strings :
		$a_81_0 = {2e 73 69 63 6b } //32 00  .sick
		$a_81_1 = {4e 65 77 52 61 6e 53 6d 57 61 72 65 } //14 00  NewRanSmWare
		$a_81_2 = {65 72 61 77 6f 73 6e 61 72 } //14 00  erawosnar
		$a_81_3 = {52 69 70 46 6f 72 59 6f 75 } //03 00  RipForYou
		$a_81_4 = {67 68 6f 73 74 62 69 6e 2e 63 6f 6d } //03 00  ghostbin.com
		$a_81_5 = {70 61 73 73 77 6f 72 64 31 32 33 } //01 00  password123
		$a_81_6 = {48 45 4c 50 2e 74 78 74 } //01 00  HELP.txt
		$a_81_7 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00  DisableTaskMgr
		$a_81_8 = {72 61 6e 73 6f 6d 2e 6a 70 67 } //00 00  ransom.jpg
	condition:
		any of ($a_*)
 
}