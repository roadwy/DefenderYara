
rule Ransom_MSIL_Cryptolocker_DX_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 09 00 00 "
		
	strings :
		$a_81_0 = {2e 73 69 63 6b } //50 .sick
		$a_81_1 = {4e 65 77 52 61 6e 53 6d 57 61 72 65 } //50 NewRanSmWare
		$a_81_2 = {65 72 61 77 6f 73 6e 61 72 } //20 erawosnar
		$a_81_3 = {52 69 70 46 6f 72 59 6f 75 } //20 RipForYou
		$a_81_4 = {67 68 6f 73 74 62 69 6e 2e 63 6f 6d } //3 ghostbin.com
		$a_81_5 = {70 61 73 73 77 6f 72 64 31 32 33 } //3 password123
		$a_81_6 = {48 45 4c 50 2e 74 78 74 } //1 HELP.txt
		$a_81_7 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_81_8 = {72 61 6e 73 6f 6d 2e 6a 70 67 } //1 ransom.jpg
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=74
 
}