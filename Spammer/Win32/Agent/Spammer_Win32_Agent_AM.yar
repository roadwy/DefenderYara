
rule Spammer_Win32_Agent_AM{
	meta:
		description = "Spammer:Win32/Agent.AM,SIGNATURE_TYPE_PEHSTR,0b 00 09 00 0b 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 44 61 74 61 5c 41 64 64 72 65 73 73 34 36 } //2 Software\Microsoft\Windows\CurrentVersion\Explorer\Data\Address46
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 44 61 74 61 5c 41 75 74 68 34 36 } //2 Software\Microsoft\Windows\CurrentVersion\Explorer\Data\Auth46
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 70 72 6e 64 72 76 2e 64 6c 6c } //1 Microsoft\Internet Explorer\prndrv.dll
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 46 69 6c 74 65 72 } //1 Software\Microsoft\Filter
		$a_01_4 = {53 63 72 69 70 74 20 65 78 65 63 75 74 69 6f 6e 20 66 61 69 6c 65 64 } //1 Script execution failed
		$a_01_5 = {5f 5f 50 52 4f 58 59 5f 4d 55 54 45 58 5f 25 64 5f 5f } //1 __PROXY_MUTEX_%d__
		$a_01_6 = {2e 53 75 62 6d 69 74 46 6f 72 6d 49 6d 61 67 65 } //1 .SubmitFormImage
		$a_01_7 = {2e 43 6c 69 63 6b 48 79 70 65 72 6c 69 6e 6b } //1 .ClickHyperlink
		$a_01_8 = {37 32 2e 32 33 32 2e 31 33 36 2e 35 39 } //1 72.232.136.59
		$a_01_9 = {2e 53 75 62 6d 69 74 46 6f 72 6d } //1 .SubmitForm
		$a_01_10 = {70 72 6f 78 79 32 2e 64 6c 6c } //1 proxy2.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=9
 
}