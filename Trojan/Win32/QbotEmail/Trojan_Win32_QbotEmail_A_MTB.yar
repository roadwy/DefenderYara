
rule Trojan_Win32_QbotEmail_A_MTB{
	meta:
		description = "Trojan:Win32/QbotEmail.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {65 6d 61 69 6c 63 6f 6c 6c 65 63 74 6f 72 5f 64 6c 6c 3a 20 44 6c 6c 4d 61 69 6e 28 29 3a 20 67 6f 74 20 44 4c 4c 5f 50 52 4f 43 45 53 53 5f 41 54 54 41 43 48 20 78 36 34 } //1 emailcollector_dll: DllMain(): got DLL_PROCESS_ATTACH x64
		$a_81_1 = {43 6f 6c 6c 65 63 74 4f 75 74 6c 6f 6f 6b 44 61 74 61 28 29 3a 20 73 74 61 72 74 65 64 20 6e 69 63 6b 3d 25 73 } //1 CollectOutlookData(): started nick=%s
		$a_81_2 = {63 6f 6c 6c 65 63 74 6f 72 5f 6c 6f 67 2e 74 78 74 } //1 collector_log.txt
		$a_81_3 = {5c 65 6d 61 69 6c 2e 74 78 74 } //1 \email.txt
		$a_81_4 = {43 6f 6c 6c 65 63 74 4f 75 74 6c 6f 6f 6b 45 6d 61 69 6c 73 28 29 3a 20 63 61 6e 6e 6f 74 20 64 65 74 65 63 74 20 63 75 72 72 65 6e 74 20 6d 73 67 20 73 74 6f 72 65 20 65 6d 61 69 6c 21 21 21 20 56 65 72 79 20 62 61 64 21 21 21 } //1 CollectOutlookEmails(): cannot detect current msg store email!!! Very bad!!!
		$a_81_5 = {61 64 64 72 65 73 73 62 6f 6f 6b 2e 74 78 74 } //1 addressbook.txt
		$a_81_6 = {63 6d 64 2e 65 78 65 20 2f 63 20 72 6d 64 69 72 20 2f 53 20 2f 51 20 22 25 73 22 } //1 cmd.exe /c rmdir /S /Q "%s"
		$a_81_7 = {25 73 5c 45 6d 61 69 6c 53 74 6f 72 61 67 65 5f 25 73 2d 25 73 5f 25 75 } //1 %s\EmailStorage_%s-%s_%u
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}