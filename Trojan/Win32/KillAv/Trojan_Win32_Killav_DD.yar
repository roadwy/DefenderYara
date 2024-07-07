
rule Trojan_Win32_Killav_DD{
	meta:
		description = "Trojan:Win32/Killav.DD,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 65 72 6d 69 6e 61 74 65 50 72 6f 63 65 73 73 } //1 TerminateProcess
		$a_01_1 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 52 75 6e 5c } //1 \Windows\CurrentVersion\policies\Explorer\Run\
		$a_01_2 = {5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 } //1 \Windows NT\CurrentVersion\Image File Execution Options
		$a_01_3 = {5c 44 65 62 75 67 67 65 72 00 00 00 ff ff ff ff 07 00 00 00 6e 74 73 64 20 2d 64 } //1
		$a_01_4 = {72 61 76 6d 6f 6e 2e 65 78 65 00 00 ff ff ff ff 0b 00 00 00 72 61 76 6d 6f 6e 64 2e 65 78 65 00 ff ff ff ff 0b 00 00 00 72 61 76 74 61 73 6b 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}