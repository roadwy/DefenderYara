
rule Trojan_BAT_Agent_UKY_MTB{
	meta:
		description = "Trojan:BAT/Agent.UKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {73 61 64 6c 69 66 65 } //1 sadlife
		$a_81_1 = {44 69 67 69 74 61 6c 6c 69 66 79 } //1 Digitallify
		$a_81_2 = {5a 68 58 6c 33 39 42 6c 68 50 38 34 2b 59 34 6b 75 72 41 38 77 70 65 68 78 78 71 41 30 58 32 32 49 4d 59 5a 36 56 70 69 71 73 } //1 ZhXl39BlhP84+Y4kurA8wpehxxqA0X22IMYZ6Vpiqs
		$a_81_3 = {77 68 79 73 6f 73 61 64 } //1 whysosad
		$a_81_4 = {64 61 76 2e 62 61 74 } //1 dav.bat
		$a_81_5 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_81_6 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 DisableAntiSpyware
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}