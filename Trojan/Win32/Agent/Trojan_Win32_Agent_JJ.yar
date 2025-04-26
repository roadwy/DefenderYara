
rule Trojan_Win32_Agent_JJ{
	meta:
		description = "Trojan:Win32/Agent.JJ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 73 76 63 68 30 73 74 31 2e 65 78 65 } //1 \svch0st1.exe
		$a_01_1 = {73 25 5c 70 6d 65 54 5c 53 57 4f 44 4e 49 57 5c 3a 43 } //1 s%\pmeT\SWODNIW\:C
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 73 73 6d 61 72 71 75 65 2e 73 63 72 } //1 C:\Program Files\Internet Explorer\ssmarque.scr
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 63 61 72 73 73 2e 65 78 65 } //1 C:\Program Files\Internet Explorer\carss.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}