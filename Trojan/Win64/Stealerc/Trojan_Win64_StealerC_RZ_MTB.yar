
rule Trojan_Win64_StealerC_RZ_MTB{
	meta:
		description = "Trojan:Win64/StealerC.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 41 56 5a 30 37 33 63 4f 6a 4c 37 46 67 70 34 75 5a 5a 61 65 } //2 Go build ID: "AVZ073cOjL7Fgp4uZZae
		$a_81_1 = {6d 61 69 6e 2e 28 2a 45 78 74 72 61 63 74 42 72 6f 77 73 65 72 50 72 6f 66 69 6c 65 29 2e 7a 69 70 55 73 65 72 44 61 74 61 } //2 main.(*ExtractBrowserProfile).zipUserData
		$a_81_2 = {2e 65 78 74 72 61 63 74 42 72 6f 77 73 65 72 44 61 74 61 } //2 .extractBrowserData
		$a_81_3 = {2e 63 6f 70 79 55 73 65 72 44 61 74 61 2e 66 75 6e 63 31 } //2 .copyUserData.func1
		$a_81_4 = {2e 6b 69 6c 6c 43 68 72 6f 6d 65 50 72 6f 63 65 73 73 65 73 2e 66 75 6e 63 31 } //1 .killChromeProcesses.func1
		$a_81_5 = {49 76 72 73 6a 7a 69 76 6a 77 64 71 6c 63 77 72 6d 62 75 6f 6f 77 69 65 62 69 6a 77 6a 6b 61 67 } //1 Ivrsjzivjwdqlcwrmbuoowiebijwjkag
		$a_81_6 = {6f 75 75 68 6c 74 71 72 64 78 6b 78 63 66 77 6e 6f 6b 69 72 61 6f 77 69 66 6f 72 75 61 76 65 66 2e 66 75 6e 63 31 } //1 ouuhltqrdxkxcfwnokiraowiforuavef.func1
		$a_81_7 = {6a 62 72 67 7a 6e 77 74 71 67 6a 75 73 62 72 75 73 64 61 67 66 73 73 69 6b 6f 67 74 6b 61 75 77 2e 66 75 6e 63 31 } //1 jbrgznwtqgjusbrusdagfssikogtkauw.func1
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=12
 
}