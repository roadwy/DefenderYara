
rule Trojan_Win32_Rapid_A_MTB{
	meta:
		description = "Trojan:Win32/Rapid.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0a 00 00 "
		
	strings :
		$a_81_0 = {21 44 45 43 52 59 50 54 5f 46 49 4c 45 53 2e 74 78 74 } //1 !DECRYPT_FILES.txt
		$a_81_1 = {43 6f 6e 67 72 61 74 75 6c 61 74 69 6f 6e 73 2c 20 79 6f 75 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } //1 Congratulations, you files have been encrypted.
		$a_81_2 = {59 6f 75 72 20 64 6f 63 75 6d 65 6e 74 73 2c 20 70 68 6f 74 6f 73 2c 20 64 61 74 61 62 61 73 65 73 20 61 6e 64 20 6f 74 68 65 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your documents, photos, databases and other important files have been encrypted
		$a_81_3 = {53 6f 66 74 77 61 72 65 5c 45 6e 63 72 79 70 74 55 49 44 } //1 Software\EncryptUID
		$a_81_4 = {46 6f 72 20 66 75 72 74 68 65 72 20 73 74 65 70 73 20 72 65 61 64 20 44 45 43 52 59 50 54 5f 46 49 4c 45 53 2e 74 78 74 } //1 For further steps read DECRYPT_FILES.txt
		$a_81_5 = {7d 5c 6e 6f 72 61 70 69 64 2e 65 78 65 } //1 }\norapid.exe
		$a_81_6 = {7d 5c 72 61 70 69 64 72 65 63 6f 76 65 72 79 2e 74 78 74 } //1 }\rapidrecovery.txt
		$a_81_7 = {2f 63 20 74 61 73 6b 6c 69 73 74 20 2f 66 69 20 22 69 6d 61 67 65 6e 61 6d 65 20 65 71 20 4d 73 4d 70 45 6e 67 2e 65 78 65 22 20 7c 20 66 69 6e 64 20 2f 63 20 22 50 49 44 22 20 26 26 20 45 63 68 6f 20 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 } //1 /c tasklist /fi "imagename eq MsMpEng.exe" | find /c "PID" && Echo Windows Defender
		$a_81_8 = {2f 63 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //1 /c vssadmin.exe Delete Shadows /All /Quiet
		$a_81_9 = {41 6c 73 6f 21 20 41 74 20 74 68 69 73 20 70 61 67 65 20 79 6f 75 20 77 69 6c 6c 20 62 65 20 61 62 6c 65 20 74 6f 20 72 65 73 74 6f 72 65 20 61 6e 79 20 6f 6e 65 20 66 69 6c 65 20 66 6f 72 20 66 72 65 65 21 } //1 Also! At this page you will be able to restore any one file for free!
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=6
 
}