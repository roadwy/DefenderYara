
rule HackTool_Win32_SmptMailStress{
	meta:
		description = "HackTool:Win32/SmptMailStress,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {50 6c 65 73 65 20 77 61 69 74 21 20 53 65 6e 74 69 6e 67 20 25 64 20 6d 61 69 6c 73 20 75 73 69 6e 67 20 25 64 20 54 68 72 65 61 64 73 20 69 73 20 73 74 61 72 74 65 64 2e 2e 2e } //Plese wait! Senting %d mails using %d Threads is started...  1
		$a_80_1 = {53 65 6e 74 20 25 64 20 74 68 20 6d 61 69 6c 20 69 73 20 66 61 69 6c 65 64 20 74 72 79 69 6e 67 20 6e 65 78 74 2e 2e 2e 2e } //Sent %d th mail is failed trying next....  1
		$a_80_2 = {53 65 6e 74 20 25 64 20 74 68 20 6d 61 69 6c 20 69 73 20 73 75 63 63 65 73 73 2e 2e 2e 2e } //Sent %d th mail is success....  1
		$a_80_3 = {48 69 72 27 73 20 53 4d 54 50 20 73 74 72 65 73 73 } //Hir's SMTP stress  1
		$a_80_4 = {53 65 6e 74 69 6e 67 20 25 64 20 6d 61 69 6c 73 20 43 6f 6d 70 6c 65 74 65 64 21 21 21 20 49 20 61 6d 20 72 65 61 64 79 20 66 6f 72 20 43 68 65 63 6b 69 6e 67 20 61 67 61 69 6e 20 21 21 21 } //Senting %d mails Completed!!! I am ready for Checking again !!!  1
		$a_80_5 = {49 20 61 6d 20 72 65 61 64 79 20 66 6f 72 20 43 68 65 63 6b 69 6e 67 20 41 67 61 69 6e 21 21 21 21 21 } //I am ready for Checking Again!!!!!  1
		$a_80_6 = {6d 69 63 72 6f 73 6f 66 74 20 5b 31 31 31 2e 31 32 32 2e 31 2e 31 32 5d } //microsoft [111.122.1.12]  2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*2) >=5
 
}