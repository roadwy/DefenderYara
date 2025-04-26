
rule Trojan_Win32_Trickbot_AR_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c1 0f b7 0f 8d 70 bf 66 83 fe 19 77 03 83 c0 20 8d 71 bf 66 83 fe 19 77 03 83 c1 20 66 3b c1 } //5
		$a_01_1 = {8b 34 b2 8b 45 08 03 f1 8a 1e 3a 18 75 18 84 db 74 10 8a 5e 01 } //5
		$a_01_2 = {8b 44 24 14 8d 0c 03 8b 44 24 1c 88 1c 08 8b c3 99 f7 7d 14 8b 45 10 43 8a 04 02 88 01 3b de } //5
		$a_81_3 = {63 3a 5c 55 73 65 72 73 5c 4d 72 2e 41 6e 64 65 72 73 6f 6e 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 30 38 5c 50 72 6f 6a 65 63 74 73 5c 41 6e 64 65 72 73 6f 6e 5c 52 65 6c 65 61 73 65 5c 41 6e 64 65 72 73 6f 6e 2e 70 64 62 } //10 c:\Users\Mr.Anderson\Documents\Visual Studio 2008\Projects\Anderson\Release\Anderson.pdb
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_81_3  & 1)*10) >=15
 
}
rule Trojan_Win32_Trickbot_AR_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 3a 5c 50 72 6f 6a 65 63 74 73 5c 57 65 62 49 6e 6a 65 63 74 5c 62 69 6e 5c 78 38 36 5c 52 65 6c 65 61 73 65 5f 6c 6f 67 67 65 64 5c 77 65 62 69 6e 6a 65 63 74 33 32 2e 70 64 62 } //10 F:\Projects\WebInject\bin\x86\Release_logged\webinject32.pdb
		$a_01_1 = {46 3a 5c 50 72 6f 6a 65 63 74 73 5c 57 65 62 49 6e 6a 65 63 74 5c 62 69 6e 5c 78 36 34 5c 52 65 6c 65 61 73 65 5f 6c 6f 67 67 65 64 5c 77 65 62 69 6e 6a 65 63 74 36 34 2e 70 64 62 } //10 F:\Projects\WebInject\bin\x64\Release_logged\webinject64.pdb
		$a_01_2 = {77 65 62 69 6e 6a 65 63 74 36 34 2e 64 6c 6c } //10 webinject64.dll
		$a_01_3 = {77 65 62 69 6e 6a 65 63 74 33 32 2e 64 6c 6c } //10 webinject32.dll
		$a_01_4 = {62 52 53 38 79 59 51 30 41 50 71 39 78 66 7a 43 } //5 bRS8yYQ0APq9xfzC
		$a_01_5 = {45 53 54 52 5f 50 41 53 53 5f } //5 ESTR_PASS_
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5) >=30
 
}