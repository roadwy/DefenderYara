
rule Trojan_Win64_ClassCuts_A_dha{
	meta:
		description = "Trojan:Win64/ClassCuts.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,fffffff4 01 fffffff4 01 05 00 00 "
		
	strings :
		$a_01_0 = {63 68 61 6e 67 65 73 68 65 6c 6c } //100 changeshell
		$a_01_1 = {73 61 76 65 64 61 74 61 } //100 savedata
		$a_01_2 = {67 65 74 66 69 6c 65 } //100 getfile
		$a_01_3 = {70 6f 73 74 66 69 6c 65 } //100 postfile
		$a_01_4 = {4e 6f 44 61 74 61 } //100 NoData
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100) >=500
 
}