
rule Trojan_BAT_Styerlown_A{
	meta:
		description = "Trojan:BAT/Styerlown.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 61 64 6f 50 72 6f 69 67 72 61 74 } //1 nadoProigrat
		$a_01_1 = {6b 65 79 62 6f 61 72 64 68 6f 6f 6b } //1 keyboardhook
		$a_01_2 = {52 75 6e 53 6f 62 79 74 } //1 RunSobyt
		$a_01_3 = {48 69 64 65 53 65 6e 64 69 6e 67 46 69 6c 65 73 } //1 HideSendingFiles
		$a_01_4 = {43 00 3a 00 5c 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 C:\WINDOWS\svchost.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}