
rule Ransom_Win64_Clop_A{
	meta:
		description = "Ransom:Win64/Clop.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6e 65 74 20 73 74 6f 70 20 6d 6f 7a 79 70 72 6f 62 61 63 6b 75 70 20 2f 79 } //1 net stop mozyprobackup /y
		$a_01_1 = {6e 65 74 20 73 74 6f 70 20 45 72 61 73 65 72 53 76 63 31 31 37 31 30 20 2f 79 } //1 net stop EraserSvc11710 /y
		$a_01_2 = {6e 65 74 20 73 74 6f 70 20 53 73 74 70 53 76 63 20 2f 79 } //1 net stop SstpSvc /y
		$a_01_3 = {6e 65 74 20 73 74 6f 70 20 4d 53 53 51 4c 53 45 52 56 45 52 20 2f 79 } //1 net stop MSSQLSERVER /y
		$a_01_4 = {6e 65 74 20 73 74 6f 70 20 53 51 4c 57 72 69 74 65 72 20 2f 79 } //1 net stop SQLWriter /y
		$a_01_5 = {74 6f 6f 20 6d 61 6e 79 20 66 69 6c 65 73 20 6f 70 65 6e 20 69 6e 20 73 79 73 74 65 6d } //1 too many files open in system
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}