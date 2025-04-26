
rule Trojan_BAT_Coinminer_WRA_MTB{
	meta:
		description = "Trojan:BAT/Coinminer.WRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 63 68 65 63 6b 69 70 2e 64 79 6e 64 6e 73 2e 6f 72 67 } //1 http://checkip.dyndns.org
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_3 = {53 74 61 72 74 58 4d 52 69 67 } //1 StartXMRig
		$a_81_4 = {50 5f 4f 75 74 70 75 74 44 61 74 61 52 65 63 65 69 76 65 64 } //1 P_OutputDataReceived
		$a_81_5 = {68 74 74 70 73 3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 32 31 31 32 34 31 34 37 32 32 3a 41 41 47 75 58 2d 48 4e 62 72 6d 54 55 42 43 51 5f 55 58 6c 4f 34 6f 2d 66 4a 48 65 72 6e 69 38 78 55 77 2f 73 65 6e 64 4d 65 73 73 61 67 65 3f 63 68 61 74 5f 69 64 3d 2d 31 30 30 31 37 37 37 37 32 33 35 35 35 26 74 65 78 74 3d } //1 https://api.telegram.org/bot2112414722:AAGuX-HNbrmTUBCQ_UXlO4o-fJHerni8xUw/sendMessage?chat_id=-1001777723555&text=
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}