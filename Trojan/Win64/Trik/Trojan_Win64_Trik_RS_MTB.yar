
rule Trojan_Win64_Trik_RS_MTB{
	meta:
		description = "Trojan:Win64/Trik.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 40 18 48 8b 40 10 48 89 44 24 60 48 8b 44 24 60 48 8b 40 30 48 8b 4c 24 58 48 03 c8 48 8b c1 48 89 44 24 58 48 8b 44 24 58 48 89 44 24 50 ff 54 24 50 } //1
		$a_81_1 = {74 65 73 74 5f 72 65 73 75 6c 74 73 2e 74 78 74 } //1 test_results.txt
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}