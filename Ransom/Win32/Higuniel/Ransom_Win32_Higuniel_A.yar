
rule Ransom_Win32_Higuniel_A{
	meta:
		description = "Ransom:Win32/Higuniel.A,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 1b 00 00 "
		
	strings :
		$a_01_0 = {23 50 72 65 52 75 6e } //1 #PreRun
		$a_01_1 = {23 50 6f 73 74 52 75 6e } //1 #PostRun
		$a_01_2 = {23 45 78 74 65 6e 73 69 6f 6e 49 67 6e 6f 72 65 } //1 #ExtensionIgnore
		$a_01_3 = {23 54 58 54 } //1 #TXT
		$a_01_4 = {52 65 61 64 4d 65 5f 44 65 63 72 79 70 74 6f 72 2e 74 78 74 } //2 ReadMe_Decryptor.txt
		$a_01_5 = {73 63 20 73 74 6f 70 20 77 73 63 73 76 63 } //4 sc stop wscsvc
		$a_01_6 = {73 63 20 73 74 6f 70 20 57 69 6e 44 65 66 65 6e 64 } //4 sc stop WinDefend
		$a_01_7 = {73 63 20 73 74 6f 70 20 77 75 61 75 73 65 72 76 } //4 sc stop wuauserv
		$a_01_8 = {73 63 20 73 74 6f 70 20 42 49 54 53 } //4 sc stop BITS
		$a_01_9 = {73 63 20 73 74 6f 70 20 45 52 53 76 63 } //4 sc stop ERSvc
		$a_01_10 = {73 63 20 73 74 6f 70 20 57 65 72 53 76 63 } //4 sc stop WerSvc
		$a_01_11 = {63 6d 64 2e 65 78 65 20 2f 63 20 62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //8 cmd.exe /c bcdedit /set {default} recoveryenabled No
		$a_01_12 = {63 6d 64 2e 65 78 65 20 2f 63 20 62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 } //8 cmd.exe /c bcdedit /set {default} bootstatuspolicy ignoreallfailures
		$a_01_13 = {63 6d 64 2e 65 78 65 20 2f 63 20 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //8 cmd.exe /c vssadmin delete shadows /all /quiet
		$a_01_14 = {63 6d 64 2e 65 78 65 20 2f 63 20 77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //8 cmd.exe /c wmic shadowcopy delete
		$a_01_15 = {63 6d 64 2e 65 78 65 20 2f 63 20 77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //8 cmd.exe /c wbadmin delete catalog -quiet
		$a_01_16 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 4d 53 45 78 63 68 61 6e 67 65 2a } //16 taskkill /f /im MSExchange*
		$a_01_17 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 4d 69 63 72 6f 73 6f 66 74 2e 45 78 63 68 61 6e 67 65 2e 2a } //16 taskkill /f /im Microsoft.Exchange.*
		$a_01_18 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 73 71 6c 73 65 72 76 65 72 2e 65 78 65 } //16 taskkill /f /im sqlserver.exe
		$a_01_19 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 73 71 6c 77 72 69 74 65 72 2e 65 78 65 } //16 taskkill /f /im sqlwriter.exe
		$a_01_20 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 64 75 65 20 74 6f 20 61 20 73 65 63 75 72 69 74 79 20 70 72 6f 62 6c 65 6d 20 77 69 74 68 20 79 6f 75 72 20 50 43 2e 20 49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 73 74 6f 72 65 20 74 68 65 6d 2c 20 77 72 69 74 65 20 75 73 20 74 6f 20 74 68 65 20 65 2d 6d 61 69 6c 20 64 65 63 72 79 70 74 6f 72 40 63 6f 63 6b 2e 6c 69 } //32 All your files have been encrypted due to a security problem with your PC. If you want to restore them, write us to the e-mail decryptor@cock.li
		$a_01_21 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 64 75 65 20 74 6f 20 61 20 73 65 63 75 72 69 74 79 20 70 72 6f 62 6c 65 6d 20 77 69 74 68 20 79 6f 75 72 20 50 43 2e 20 49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 73 74 6f 72 65 20 74 68 65 6d 2c 20 77 72 69 74 65 20 75 73 20 74 6f 20 74 68 65 20 65 2d 6d 61 69 6c 3a 20 61 69 64 63 6f 6d 70 61 6e 79 40 74 75 74 61 6e 6f 74 61 2e 63 6f 6d } //32 All your files have been encrypted due to a security problem with your PC. If you want to restore them, write us to the e-mail: aidcompany@tutanota.com
		$a_01_22 = {49 6e 20 63 61 73 65 20 6f 66 20 6e 6f 20 61 6e 73 77 65 72 20 69 6e 20 32 34 20 68 6f 75 72 73 20 77 72 69 74 65 20 75 73 20 74 6f 20 74 68 65 65 73 65 20 65 2d 6d 61 69 6c 73 3a 20 6d 61 73 74 65 72 64 65 63 72 79 70 74 40 6f 70 65 6e 6d 61 69 6c 62 6f 78 2e 6f 72 67 } //32 In case of no answer in 24 hours write us to theese e-mails: masterdecrypt@openmailbox.org
		$a_01_23 = {49 6e 20 63 61 73 65 20 6f 66 20 6e 6f 20 61 6e 73 77 65 72 20 69 6e 20 34 38 20 68 6f 75 72 73 20 77 72 69 74 65 20 75 73 20 74 6f 20 74 68 65 65 73 65 20 65 2d 6d 61 69 6c 73 3a 20 61 69 64 63 6f 6d 70 61 6e 75 40 63 6f 63 6b 2e 6c 69 } //32 In case of no answer in 48 hours write us to theese e-mails: aidcompanu@cock.li
		$a_01_24 = {59 6f 75 20 68 61 76 65 20 74 6f 20 70 61 79 20 66 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 20 69 6e 20 42 69 74 63 6f 69 6e 73 2e 20 54 68 65 20 70 72 69 63 65 20 64 65 70 65 6e 64 73 20 6f 6e 20 68 6f 77 20 66 61 73 74 20 79 6f 75 20 77 72 69 74 65 20 74 6f 20 75 73 2e } //32 You have to pay for decryption in Bitcoins. The price depends on how fast you write to us.
		$a_01_25 = {42 65 66 6f 72 65 20 70 61 79 69 6e 67 20 79 6f 75 20 63 61 6e 20 73 65 6e 64 20 75 73 20 75 70 20 74 6f 20 35 20 66 69 6c 65 73 20 66 6f 72 20 66 72 65 65 20 64 65 63 72 79 70 74 69 6f 6e 2e } //32 Before paying you can send us up to 5 files for free decryption.
		$a_01_26 = {41 66 74 65 72 20 70 61 79 6d 65 6e 74 20 77 65 20 77 69 6c 6c 20 73 65 6e 64 20 79 6f 75 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 74 6f 6f 6c 20 74 68 61 74 20 77 69 6c 6c 20 64 65 63 72 79 70 74 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 2e } //32 After payment we will send you the decryption tool that will decrypt all your files.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*4+(#a_01_6  & 1)*4+(#a_01_7  & 1)*4+(#a_01_8  & 1)*4+(#a_01_9  & 1)*4+(#a_01_10  & 1)*4+(#a_01_11  & 1)*8+(#a_01_12  & 1)*8+(#a_01_13  & 1)*8+(#a_01_14  & 1)*8+(#a_01_15  & 1)*8+(#a_01_16  & 1)*16+(#a_01_17  & 1)*16+(#a_01_18  & 1)*16+(#a_01_19  & 1)*16+(#a_01_20  & 1)*32+(#a_01_21  & 1)*32+(#a_01_22  & 1)*32+(#a_01_23  & 1)*32+(#a_01_24  & 1)*32+(#a_01_25  & 1)*32+(#a_01_26  & 1)*32) >=42
 
}