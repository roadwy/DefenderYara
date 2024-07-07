
rule Trojan_BAT_SnakeKeylogger_NY_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {02 73 21 00 00 0a 0a 73 22 00 00 0a 0b 06 16 73 23 00 00 0a 73 24 00 00 0a 0c 08 07 6f 25 00 00 0a de 0a } //1
		$a_01_1 = {6f 00 6e 00 65 00 6c 00 69 00 6e 00 65 00 72 00 73 00 2e 00 65 00 78 00 65 00 } //1 oneliners.exe
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_3 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //1 CreateDelegate
		$a_01_4 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}