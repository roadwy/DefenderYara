
rule TrojanProxy_Win32_Horst_YA{
	meta:
		description = "TrojanProxy:Win32/Horst.YA,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 0b 00 00 "
		
	strings :
		$a_00_0 = {6a 61 76 61 73 63 72 69 70 74 3a 74 6f 70 2e 70 61 72 65 6e 74 2e 6c 6f 63 61 74 69 6f 6e 3d 27 68 74 74 70 3a 2f 2f } //1 javascript:top.parent.location='http://
		$a_00_1 = {49 00 6e 00 76 00 61 00 6c 00 69 00 64 00 20 00 53 00 63 00 72 00 65 00 65 00 6e 00 20 00 4e 00 61 00 6d 00 65 00 20 00 6f 00 72 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 2e 00 20 00 50 00 6c 00 65 00 61 00 73 00 65 00 20 00 74 00 72 00 79 00 20 00 61 00 67 00 61 00 69 00 6e 00 2e 00 } //1 Invalid Screen Name or Password. Please try again.
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 } //1 Software\Microsoft\Windows\CurrentVersion\Internet Settings
		$a_00_3 = {59 00 6f 00 75 00 72 00 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 20 00 77 00 61 00 73 00 20 00 6e 00 6f 00 74 00 20 00 73 00 65 00 6e 00 74 00 2e 00 20 00 50 00 6c 00 65 00 61 00 73 00 65 00 20 00 63 00 6c 00 69 00 63 00 6b 00 20 00 6f 00 6e 00 20 00 74 00 68 00 65 00 20 00 75 00 72 00 6c 00 20 00 62 00 65 00 6c 00 6f 00 77 00 2c 00 20 00 63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 20 00 74 00 68 00 65 00 20 00 69 00 6d 00 61 00 67 00 65 00 20 00 70 00 75 00 7a 00 7a 00 6c 00 65 00 2c 00 20 00 61 00 6e 00 64 00 20 00 74 00 68 00 65 00 6e 00 20 00 72 00 65 00 73 00 65 00 6e 00 64 00 20 00 79 00 6f 00 75 00 72 00 20 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 2e 00 } //1 Your message was not sent. Please click on the url below, complete the image puzzle, and then resend your message.
		$a_00_4 = {76 00 61 00 72 00 20 00 62 00 63 00 63 00 4c 00 69 00 73 00 74 00 20 00 3d 00 20 00 5b 00 5d 00 3b 00 } //1 var bccList = [];
		$a_00_5 = {76 00 61 00 72 00 20 00 63 00 63 00 4c 00 69 00 73 00 74 00 20 00 3d 00 20 00 5b 00 5d 00 3b 00 } //1 var ccList = [];
		$a_01_6 = {4e 6f 52 65 6d 6f 76 65 } //1 NoRemove
		$a_01_7 = {53 65 6e 64 46 6f 72 6d } //1 SendForm
		$a_01_8 = {6c 6f 67 69 6e 49 64 } //1 loginId
		$a_00_9 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 6f 6c 2e 63 6f 6d 2f } //1 http://www.aol.com/
		$a_00_10 = {45 00 6e 00 74 00 65 00 72 00 20 00 74 00 68 00 65 00 20 00 63 00 68 00 61 00 72 00 61 00 63 00 74 00 65 00 72 00 73 00 20 00 69 00 6e 00 20 00 74 00 68 00 65 00 20 00 69 00 6d 00 61 00 67 00 65 00 20 00 20 00 62 00 65 00 6c 00 6f 00 77 00 20 00 77 00 69 00 74 00 68 00 6f 00 75 00 74 00 20 00 61 00 6e 00 79 00 20 00 73 00 70 00 61 00 63 00 65 00 73 00 3a 00 } //1 Enter the characters in the image  below without any spaces:
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=9
 
}