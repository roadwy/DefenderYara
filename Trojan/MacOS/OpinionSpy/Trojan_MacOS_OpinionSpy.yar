
rule Trojan_MacOS_OpinionSpy{
	meta:
		description = "Trojan:MacOS/OpinionSpy,SIGNATURE_TYPE_MACHOHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 65 63 75 72 65 73 74 75 64 69 65 73 2e 63 6f 6d } //2 securestudies.com
		$a_00_1 = {53 75 72 76 65 79 51 75 65 73 74 69 6f 6e 56 69 65 77 43 6f 6e 74 72 6f 6c 6c 65 72 } //1 SurveyQuestionViewController
		$a_00_2 = {50 72 65 6d 69 65 72 4f 70 69 6e 69 6f 6e } //3 PremierOpinion
		$a_00_3 = {70 6f 44 65 6d 6f 2e 74 78 74 } //1 poDemo.txt
		$a_00_4 = {2f 70 72 69 76 61 74 65 2f 74 6d 70 2f } //1 /private/tmp/
		$a_00_5 = {50 6c 65 61 73 65 20 63 6f 6d 70 6c 65 74 65 20 74 68 69 73 20 73 68 6f 72 74 20 73 75 72 76 65 79 } //1 Please complete this short survey
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*3+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=9
 
}